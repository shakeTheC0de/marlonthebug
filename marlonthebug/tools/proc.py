"""Subprocess execution shared by local and containerised tool runners.

Only standard-library modules are used so the file can be copied into the Kali
tools image next to ``runner_api.py`` without installing the panel.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # pragma: no cover - Windows does not have pty
    import pty
except ImportError:  # pragma: no cover
    pty = None  # type: ignore[assignment]

READ_CHUNK = 65536


@dataclass(slots=True)
class ProcessResult:
    output: str
    returncode: int
    duration: float
    timed_out: bool = False
    truncated: bool = False
    error: str = ""


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _terminate(proc: asyncio.subprocess.Process) -> None:
    if os.name == "posix":
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError, OSError):
        proc.kill()


async def _drain(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    stored = 0
    total = 0
    truncated = False
    while True:
        chunk = await stream.read(READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if stored < limit:
            take = chunk[: limit - stored]
            chunks.append(take)
            stored += len(take)
        if total > limit:
            truncated = True
    return b"".join(chunks), truncated


async def run_process(
    command: list[str],
    *,
    cwd: Path,
    timeout: float,
    tty: bool = False,
    max_output: int = 60000,
    env: dict[str, str] | None = None,
) -> ProcessResult:
    """Run a command without a shell, capturing bounded output."""
    started = time.monotonic()
    child_env: dict[str, str] = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        **(env or {}),
    }
    kwargs: dict[str, Any] = {}
    if os.name == "posix":
        # Own process group so timeouts also kill child processes.
        kwargs["start_new_session"] = True

    if tty and os.name == "posix" and pty is not None:
        result = await _run_pty(
            command,
            cwd=cwd,
            timeout=timeout,
            max_output=max_output,
            env=child_env,
            started=started,
            kwargs=kwargs,
        )
        if result is not None:
            return result

    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(cwd),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=child_env,
            **kwargs,
        )
    except Exception as exc:
        return ProcessResult("", -1, time.monotonic() - started, error=str(exc))

    if proc.stdout is None:  # pragma: no cover - defensive
        return ProcessResult("", -1, time.monotonic() - started, error="No se pudo capturar la salida")

    reader = asyncio.create_task(_drain(proc.stdout, max_output))
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except TimeoutError:
        timed_out = True
        _terminate(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=5)
    except Exception as exc:
        _terminate(proc)
        with contextlib.suppress(Exception):
            await proc.wait()
        reader.cancel()
        return ProcessResult("", -1, time.monotonic() - started, error=str(exc))

    data, truncated = await reader
    duration = time.monotonic() - started
    error = f"Tiempo máximo de {timeout:g}s excedido" if timed_out else ""
    return ProcessResult(
        output=_decode(data),
        returncode=proc.returncode if proc.returncode is not None else -1,
        duration=duration,
        timed_out=timed_out,
        truncated=truncated,
        error=error,
    )


async def _run_pty(
    command: list[str],
    *,
    cwd: Path,
    timeout: float,
    max_output: int,
    env: dict[str, str],
    started: float,
    kwargs: dict[str, Any],
) -> ProcessResult | None:
    """Run with a pseudo-terminal because some tools (commix) require a TTY."""
    assert pty is not None
    master, slave = pty.openpty()
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(cwd),
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            **kwargs,
        )
    except Exception as exc:
        os.close(master)
        os.close(slave)
        return ProcessResult("", -1, time.monotonic() - started, error=str(exc))

    os.close(slave)
    os.set_blocking(master, False)
    loop = asyncio.get_running_loop()
    chunks: list[bytes] = []
    stored = 0
    total = 0
    truncated = False
    eof = asyncio.Event()

    def _read_ready() -> None:
        nonlocal stored, total, truncated
        while True:
            try:
                chunk = os.read(master, READ_CHUNK)
            except BlockingIOError:
                return
            except OSError:
                eof.set()
                with contextlib.suppress(Exception):
                    loop.remove_reader(master)
                return
            if not chunk:
                eof.set()
                with contextlib.suppress(Exception):
                    loop.remove_reader(master)
                return
            total += len(chunk)
            if stored < max_output:
                take = chunk[: max_output - stored]
                chunks.append(take)
                stored += len(take)
            if total > max_output:
                truncated = True

    loop.add_reader(master, _read_ready)
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except TimeoutError:
        timed_out = True
        _terminate(proc)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=5)
    except Exception as exc:
        _terminate(proc)
        with contextlib.suppress(Exception):
            await proc.wait()
        with contextlib.suppress(Exception):
            loop.remove_reader(master)
        os.close(master)
        return ProcessResult("", -1, time.monotonic() - started, error=str(exc))

    # Give the reader a brief chance to consume the final bytes. A background
    # child may keep the pty open, so never wait indefinitely.
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(eof.wait(), timeout=2)
    with contextlib.suppress(Exception):
        loop.remove_reader(master)
    os.close(master)

    duration = time.monotonic() - started
    error = f"Tiempo máximo de {timeout:g}s excedido" if timed_out else ""
    return ProcessResult(
        output=_decode(b"".join(chunks)),
        returncode=proc.returncode if proc.returncode is not None else -1,
        duration=duration,
        timed_out=timed_out,
        truncated=truncated,
        error=error,
    )
