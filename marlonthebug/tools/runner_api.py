"""Standalone HTTP service that executes allowlisted security tools.

The panel never mounts the Docker socket.  It delegates tool execution to this
small FastAPI service, which runs inside the Kali tools container and exposes
only two endpoints on the internal Compose network:

* ``GET  /healthz`` — readiness and tool inventory.
* ``POST /run``     — authenticated, allowlisted command execution.

This module only depends on FastAPI, uvicorn and the standard library so it can
be copied into the tools image without installing the panel.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from marlonthebug.tools.proc import ProcessResult, run_process

try:
    import marlonthebug

    VERSION = marlonthebug.__version__
except Exception:  # pragma: no cover - standalone fallback
    VERSION = "2.0.0"

TOKEN_ENV = "MTB_TOOLS_TOKEN"
MAX_BODY_BYTES = 64 * 1024
MAX_ARGS = 64
MAX_ARG_CHARS = 4096
MIN_TIMEOUT = 5
MAX_TIMEOUT = 900
HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]/-]+$")
URL_RE = re.compile(r"(?i)^https?://\S+$")


@dataclass(frozen=True)
class ToolPolicy:
    key: str
    flags: dict[str, str | None] = field(default_factory=dict)
    target_kind: str = "url"  # url, host or any
    tty: bool = False


TOOL_POLICIES: dict[str, ToolPolicy] = {
    "sqlmap": ToolPolicy(
        key="sqlmap",
        flags={
            "-u": URL_RE.pattern,
            "--batch": None,
            "--dbs": None,
            "--flush-session": None,
            "--level": r"^[1-5]$",
            "--risk": r"^[1-3]$",
            "--threads": r"^([1-9]|10)$",
            "--timeout": r"^([1-9]|[1-9][0-9]|1[01][0-9]|120)$",
            "--retries": r"^[0-5]$",
            "--output-dir": r"^(\.|/work(/[A-Za-z0-9._-]+)?)$",
            "--forms": None,
            "--crawl": r"^[0-3]$",
        },
        target_kind="url",
    ),
    "nuclei": ToolPolicy(
        key="nuclei",
        flags={
            "-u": URL_RE.pattern,
            "-jsonl": None,
            "-silent": None,
            "-no-color": None,
            "-timeout": r"^([1-9]|[1-9][0-9]|1[01][0-9]|120)$",
            "-retries": r"^[0-5]$",
            "-severity": r"^(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$",
            "-tags": r"^[A-Za-z0-9_,-]+$",
        },
        target_kind="url",
    ),
    "commix": ToolPolicy(
        key="commix",
        flags={
            "--url": URL_RE.pattern,
            "--batch": None,
            "--level": r"^[1-5]$",
            "--os-cmd": r"^(id|whoami|uname -a|echo mtb)$",
            "--timeout": r"^([1-9]|[1-9][0-9]|1[01][0-9]|120)$",
        },
        target_kind="url",
        tty=True,
    ),
    "whatweb": ToolPolicy(
        key="whatweb",
        flags={
            "--no-errors": None,
            "--color": r"^(auto|always|never)$",
            "--aggression": r"^[1-4]$",
        },
        target_kind="any",
    ),
    "nikto": ToolPolicy(
        key="nikto",
        flags={
            "-h": r"^(https?://\S+|[A-Za-z0-9._:\[\]/-]+)$",
            "-maxtime": r"^[0-9]{1,4}s$",
            "-nointeractive": None,
            "-Tuning": r"^[0-9a-x]+$",
        },
        target_kind="any",
    ),
    "nmap": ToolPolicy(
        key="nmap",
        flags={
            "-Pn": None,
            "-sV": None,
            "-T4": None,
            "-p": r"^[0-9,-]+$",
            "--top-ports": r"^([1-9][0-9]{0,3})$",
            "--version-light": None,
        },
        target_kind="host",
    ),
}


class ToolValidationError(ValueError):
    """Raised when a caller sends a command outside the allowlist."""


@dataclass(slots=True)
class RunRequest:
    tool: str
    args: list[str]
    target: str
    timeout: int
    command: list[str]


def _env_int(name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        return default
    return max(low, min(high, value))


DEFAULT_TIMEOUT = _env_int("MTB_TOOLS_TIMEOUT", 180, MIN_TIMEOUT, MAX_TIMEOUT)


def _work_root() -> Path:
    candidates: list[Path] = []
    if configured := os.environ.get("MTB_TOOLS_WORKDIR"):
        candidates.append(Path(configured))
    candidates += [Path("/work"), Path(tempfile.gettempdir()) / "mtb-tools"]
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            descriptor, probe_name = tempfile.mkstemp(prefix=".mtb-probe-", dir=candidate)
            os.close(descriptor)
            Path(probe_name).unlink()
            return candidate
        except OSError:
            continue
    raise RuntimeError("No hay un directorio de trabajo escribible (MTB_TOOLS_WORKDIR)")


def _authorized(request: Request) -> bool:
    token = os.environ.get(TOKEN_ENV, "")
    if not token:
        # Fail closed: never accept unauthenticated executions.
        return False
    header = request.headers.get("authorization", "")
    provided = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not provided:
        provided = request.headers.get("x-mtb-token", "")
    return bool(provided) and hmac.compare_digest(provided, token)


def _validate_target(policy: ToolPolicy, target: str) -> None:
    if not target or len(target) > MAX_ARG_CHARS:
        raise ToolValidationError("Objetivo vacío o demasiado largo")
    if any(char in target for char in ("\x00", "\n", "\r")) or any(char.isspace() for char in target):
        raise ToolValidationError("El objetivo contiene caracteres no permitidos")
    parsed = urlparse(target)
    if "://" in target:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ToolValidationError("Solo se admiten URLs http/https")
        return
    if policy.target_kind == "url":
        raise ToolValidationError("El objetivo debe ser una URL http/https")
    if not HOST_RE.match(target):
        raise ToolValidationError("El objetivo no es un host o red válida")


def _match_flag(policy: ToolPolicy, token: str) -> tuple[str, str | None] | None:
    if token in policy.flags:
        return token, None
    if token.startswith("--") and "=" in token:
        name, _, value = token.partition("=")
        if name in policy.flags and policy.flags[name] is not None:
            return name, value
    return None


def validate_run_request(payload: Any) -> RunRequest:
    """Validate a JSON payload against the tool allowlist.

    The runner never invokes a shell.  Validation is still strict because a
    compromised panel token should not turn the runner into a generic command
    execution service.
    """
    if not isinstance(payload, dict):
        raise ToolValidationError("El cuerpo debe ser un objeto JSON")
    unknown = set(payload) - {"tool", "args", "target", "timeout", "tty"}
    if unknown:
        raise ToolValidationError(f"Campos no permitidos: {', '.join(sorted(unknown))}")

    tool = payload.get("tool")
    if not isinstance(tool, str) or tool not in TOOL_POLICIES:
        raise ToolValidationError(f"Herramienta no permitida: {tool}")
    policy = TOOL_POLICIES[tool]

    args = payload.get("args")
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise ToolValidationError("args debe ser una lista de cadenas")
    if not 1 <= len(args) <= MAX_ARGS:
        raise ToolValidationError(f"args debe contener entre 1 y {MAX_ARGS} elementos")
    if args[0] != tool:
        raise ToolValidationError("El primer argumento debe ser el nombre de la herramienta")
    for item in args:
        if len(item) > MAX_ARG_CHARS:
            raise ToolValidationError("Un argumento supera el tamaño permitido")
        if any(char in item for char in ("\x00", "\n", "\r")):
            raise ToolValidationError("Un argumento contiene caracteres de control")

    target = payload.get("target")
    if not isinstance(target, str):
        raise ToolValidationError("target es obligatorio")
    _validate_target(policy, target)

    timeout = payload.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        raise ToolValidationError("timeout debe ser un entero")
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ToolValidationError(f"timeout debe estar entre {MIN_TIMEOUT} y {MAX_TIMEOUT} segundos")

    found_target = False
    parsed_target = urlparse(target)
    target_candidates = {target}
    if policy.target_kind == "host" and parsed_target.hostname:
        target_candidates.add(parsed_target.hostname)
        if ":" in parsed_target.hostname:
            target_candidates.add(f"[{parsed_target.hostname}]")
        if parsed_target.netloc:
            target_candidates.add(parsed_target.netloc)
    index = 1
    while index < len(args):
        token = args[index]
        if token.startswith("-"):
            matched = _match_flag(policy, token)
            if matched is None:
                raise ToolValidationError(f"Argumento no permitido: {token}")
            name, inline_value = matched
            pattern = policy.flags[name]
            if pattern is None:
                if inline_value is not None:
                    raise ToolValidationError(f"El argumento {name} no acepta valor")
            else:
                value = inline_value
                if value is None:
                    index += 1
                    if index >= len(args):
                        raise ToolValidationError(f"Falta el valor de {name}")
                    value = args[index]
                if not re.fullmatch(pattern, value):
                    raise ToolValidationError(f"Valor no permitido para {name}: {value[:80]}")
            index += 1
            continue
        if token not in target_candidates:
            raise ToolValidationError(f"Valor posicional no permitido: {token[:80]}")
        found_target = True
        index += 1

    if not found_target:
        # Target may be embedded in an --url=<target> argument.
        found_target = any(
            item in target_candidates or any(item.endswith(f"={candidate}") for candidate in target_candidates)
            for item in args[1:]
        )
    if not found_target:
        raise ToolValidationError("El objetivo no aparece en los argumentos")

    return RunRequest(tool=tool, args=args, target=target, timeout=timeout, command=list(args))


async def execute_tool(request: RunRequest) -> dict[str, Any]:
    """Execute a validated request and return raw output for the panel."""
    policy = TOOL_POLICIES[request.tool]
    executable = shutil.which(request.tool)
    if not executable:
        return {
            "tool": request.tool,
            "command": request.command,
            "output": "",
            "error": f"{request.tool} no está instalado en el tools-runner",
            "returncode": -1,
            "duration": 0.0,
            "timed_out": False,
            "truncated": False,
        }

    try:
        work_root = _work_root()
        run_dir = Path(tempfile.mkdtemp(prefix=f"{request.tool}-", dir=work_root))
    except Exception as exc:
        return {
            "tool": request.tool,
            "command": request.command,
            "output": "",
            "error": f"No se pudo preparar el directorio de trabajo: {exc}",
            "returncode": -1,
            "duration": 0.0,
            "timed_out": False,
            "truncated": False,
        }
    home = work_root / ".home"
    for directory in (home, work_root / ".cache", work_root / ".config"):
        directory.mkdir(exist_ok=True)
    # Nuclei stores its templates in $HOME at build time. The runtime home is a
    # writable tmpfs, so expose the read-only templates through a symlink.
    template_dir = Path("/home/mtb/nuclei-templates")
    template_link = home / "nuclei-templates"
    if template_dir.is_dir() and not template_link.exists():
        with contextlib.suppress(OSError):
            template_link.symlink_to(template_dir, target_is_directory=True)
    env = {
        "HOME": str(home),
        "XDG_CACHE_HOME": str(work_root / ".cache"),
        "XDG_CONFIG_HOME": str(work_root / ".config"),
        "TERM": "xterm" if policy.tty else "dumb",
        "NO_COLOR": "1",
    }
    try:
        result: ProcessResult = await run_process(
            request.command,
            cwd=run_dir,
            timeout=request.timeout,
            tty=policy.tty,
            max_output=_env_int("MTB_TOOLS_MAX_OUTPUT", 60000, 1000, 1_000_000),
            env=env,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "tool": request.tool,
            "command": request.command,
            "output": "",
            "error": str(exc),
            "returncode": -1,
            "duration": 0.0,
            "timed_out": False,
            "truncated": False,
        }
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    return {
        "tool": request.tool,
        "command": request.command,
        "output": result.output,
        "error": result.error,
        "returncode": result.returncode,
        "duration": round(result.duration, 3),
        "timed_out": result.timed_out,
        "truncated": result.truncated,
    }


app = FastAPI(
    title="MarlonTheBug tools-runner",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _get_semaphore() -> asyncio.Semaphore:
    semaphore = getattr(app.state, "tool_semaphore", None)
    if semaphore is None:
        semaphore = asyncio.Semaphore(_env_int("MTB_TOOLS_CONCURRENCY", 2, 1, 8))
        app.state.tool_semaphore = semaphore
    return semaphore


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    try:
        workdir = str(_work_root())
        status = "ok"
        reason = ""
    except Exception as exc:
        workdir = ""
        status = "degraded"
        reason = str(exc)
    return {
        "status": status,
        "reason": reason,
        "version": VERSION,
        "backend": "tools-runner",
        "workdir": workdir,
        "tools": sorted(TOOL_POLICIES),
    }


@app.post("/run", response_model=None)
async def run_tool(request: Request) -> dict[str, Any] | JSONResponse:
    if not _authorized(request):
        return JSONResponse({"detail": "Token inválido o ausente"}, status_code=401)

    declared = request.headers.get("content-length")
    if declared is not None:
        with contextlib.suppress(ValueError):
            if int(declared) > MAX_BODY_BYTES:
                return JSONResponse({"detail": "Cuerpo de petición demasiado grande"}, status_code=413)

    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "Cuerpo de petición demasiado grande"}, status_code=413)
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return JSONResponse({"detail": "JSON inválido"}, status_code=400)

    try:
        validated = validate_run_request(payload)
    except ToolValidationError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    semaphore = _get_semaphore()
    if semaphore.locked():
        return JSONResponse({"detail": "El tools-runner está ocupado; reintenta en unos segundos"}, status_code=429)
    async with semaphore:
        return await execute_tool(validated)


def serve(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Run the service with uvicorn."""
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level=os.environ.get("MTB_LOG_LEVEL", "info"))


if __name__ == "__main__":
    serve(
        os.environ.get("MTB_TOOLS_HOST", "0.0.0.0"),
        int(os.environ.get("MTB_TOOLS_PORT", "8080")),
    )
