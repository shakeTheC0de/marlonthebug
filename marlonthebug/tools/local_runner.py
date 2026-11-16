"""Run tools installed directly on the host (development and lab use)."""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path

from marlonthebug.settings import ToolSettings
from marlonthebug.tools.base import (
    ToolResult,
    classify_output,
    clean_output,
    extract_output_highlights,
    truncate_output,
)
from marlonthebug.tools.catalog import TOOLS
from marlonthebug.tools.proc import run_process


class LocalToolRunner:
    """Execute tools from ``PATH`` without a container."""

    backend = "local"

    def __init__(self, settings: ToolSettings) -> None:
        self.settings = settings

    async def status(self) -> dict:
        tools = {key: bool(shutil.which(key)) for key in TOOLS}
        available = any(tools.values())
        missing = [key for key, found in tools.items() if not found]
        return {
            "available": available and self.settings.enabled,
            "backend": self.backend,
            "version": "local",
            "image": "",
            "image_ready": True,
            "tools": tools,
            "reason": f"Faltan herramientas locales: {', '.join(missing)}" if missing else "",
        }

    async def run(self, tool: str, args: list[str], target_url: str, tty: bool = False) -> ToolResult:
        if not self.settings.enabled:
            return ToolResult(tool, False, "", {}, error="Las herramientas externas están desactivadas")
        if not args:
            return ToolResult(tool, False, "", {}, error="No hay comando que ejecutar")
        executable = shutil.which(args[0])
        if not executable:
            return ToolResult(
                tool,
                False,
                "",
                {"backend": self.backend, "target": target_url},
                error=f"{args[0]} no está instalado en PATH. Usa el backend docker o remote.",
            )

        workdir = Path(tempfile.mkdtemp(prefix="mtb-local-tool-"))
        started = time.monotonic()
        try:
            result = await run_process(
                [executable, *args[1:]],
                cwd=workdir,
                timeout=self.settings.timeout,
                tty=tty,
                max_output=self.settings.max_output_chars,
                env={"NO_COLOR": "1"},
            )
            duration = time.monotonic() - started
            output = truncate_output(clean_output(result.output), self.settings.max_output_chars)
            success, reason = classify_output(tool, output)
            error = result.error
            if not success and not error:
                error = reason
            return ToolResult(
                tool=tool,
                success=success and not result.timed_out,
                output=output,
                evidence={
                    "tool": tool,
                    "target": target_url,
                    "backend": self.backend,
                    "command": [executable, *args[1:]],
                    "returncode": result.returncode,
                    "duration": round(duration, 2),
                    "classification": reason,
                    "highlights": extract_output_highlights(output),
                    "truncated": result.truncated,
                    "timed_out": result.timed_out,
                    "output_file": str(workdir),
                },
                error=error,
                duration=duration,
                command=[executable, *args[1:]],
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
