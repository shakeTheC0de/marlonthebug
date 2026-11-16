"""HTTP client for the isolated ``tools-runner`` service."""

from __future__ import annotations

import time
from typing import Any

import httpx

from marlonthebug.settings import ToolSettings
from marlonthebug.tools.base import (
    ToolResult,
    classify_output,
    clean_output,
    extract_output_highlights,
    truncate_output,
)


class RemoteToolRunner:
    """Delegate tool execution to the internal tools-runner API."""

    backend = "remote"

    def __init__(self, settings: ToolSettings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self._transport = transport

    @property
    def base_url(self) -> str:
        return self.settings.remote_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.settings.remote_token}",
            "Accept": "application/json",
            "User-Agent": "MarlonTheBug-tools-client/2.0",
        }

    def _client(self, timeout: float) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=timeout,
            headers=self._headers(),
            transport=self._transport,
            follow_redirects=False,
        )

    def _config_error(self) -> str:
        if not self.settings.enabled:
            return "Las herramientas externas están desactivadas"
        if not self.base_url:
            return "El backend remote no tiene MTB_TOOLS_URL configurada"
        if not self.settings.remote_token:
            return "El backend remote no tiene MTB_TOOLS_TOKEN configurado"
        return ""

    async def status(self) -> dict:
        if error := self._config_error():
            return {
                "available": False,
                "backend": self.backend,
                "reason": error,
                "url": self.base_url,
                "image": "",
                "image_ready": False,
            }
        try:
            async with self._client(timeout=5) as client:
                response = await client.get(f"{self.base_url}/healthz")
        except Exception as exc:
            return {
                "available": False,
                "backend": self.backend,
                "reason": f"tools-runner no disponible: {exc}",
                "url": self.base_url,
                "image": "",
                "image_ready": False,
            }
        if response.status_code != 200:
            return {
                "available": False,
                "backend": self.backend,
                "reason": f"tools-runner respondió HTTP {response.status_code}",
                "url": self.base_url,
                "image": "",
                "image_ready": False,
            }
        data: Any
        try:
            data = response.json()
        except ValueError:
            data = {}
        payload = data if isinstance(data, dict) else {}
        available = payload.get("status") == "ok"
        return {
            "available": available,
            "backend": self.backend,
            "reason": "" if available else str(payload.get("reason", "tools-runner degradado")),
            "url": self.base_url,
            "version": str(payload.get("version", "")),
            "tools": payload.get("tools", []),
            "image": "",
            "image_ready": available,
        }

    async def run(self, tool: str, args: list[str], target_url: str, tty: bool = False) -> ToolResult:
        if error := self._config_error():
            return ToolResult(tool, False, "", {"backend": self.backend, "target": target_url}, error=error)

        payload = {
            "tool": tool,
            "args": args,
            "target": target_url,
            "timeout": self.settings.timeout,
            "tty": tty,
        }
        started = time.monotonic()
        try:
            async with self._client(timeout=self.settings.timeout + 30) as client:
                response = await client.post(f"{self.base_url}/run", json=payload)
        except httpx.TimeoutException:
            return ToolResult(
                tool,
                False,
                "",
                {"backend": self.backend, "target": target_url, "runner": self.base_url},
                error=f"El tools-runner no respondió en {self.settings.timeout + 30}s",
                duration=time.monotonic() - started,
            )
        except Exception as exc:
            return ToolResult(
                tool,
                False,
                "",
                {"backend": self.backend, "target": target_url, "runner": self.base_url},
                error=f"No se pudo contactar con tools-runner: {exc}",
                duration=time.monotonic() - started,
            )

        if response.status_code != 200:
            return ToolResult(
                tool,
                False,
                "",
                {
                    "backend": self.backend,
                    "target": target_url,
                    "runner": self.base_url,
                    "http_status": response.status_code,
                },
                error=_error_detail(response),
                duration=time.monotonic() - started,
            )

        data: Any
        try:
            data = response.json()
        except ValueError:
            return ToolResult(
                tool,
                False,
                "",
                {"backend": self.backend, "target": target_url, "runner": self.base_url},
                error="tools-runner devolvió una respuesta que no es JSON",
                duration=time.monotonic() - started,
            )
        if not isinstance(data, dict):
            return ToolResult(
                tool,
                False,
                "",
                {"backend": self.backend, "target": target_url, "runner": self.base_url},
                error="tools-runner devolvió una respuesta inválida",
                duration=time.monotonic() - started,
            )

        output = truncate_output(clean_output(str(data.get("output", ""))), self.settings.max_output_chars)
        runner_error = str(data.get("error", "") or "")
        success, reason = classify_output(tool, output)
        if not success and not runner_error:
            runner_error = reason
        duration = _as_float(data.get("duration"), time.monotonic() - started)
        returncode = _as_int(data.get("returncode"), -1)
        command = data.get("command")
        command_list = [str(item) for item in command] if isinstance(command, list) else [tool, *args]
        return ToolResult(
            tool=tool,
            success=success and not bool(data.get("timed_out")),
            output=output,
            evidence={
                "tool": tool,
                "target": target_url,
                "backend": self.backend,
                "runner": self.base_url,
                "command": command_list,
                "returncode": returncode,
                "duration": round(duration, 2),
                "classification": reason,
                "highlights": extract_output_highlights(output),
                "truncated": bool(data.get("truncated")),
                "timed_out": bool(data.get("timed_out")),
                "output_file": "",
            },
            error=runner_error,
            duration=duration,
            command=command_list,
        )


def _error_detail(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict) and payload.get("detail"):
        return str(payload["detail"])
    text = response.text.strip()
    return text[:300] if text else f"tools-runner respondió HTTP {response.status_code}"


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
