"""Service layer for running real security tools in Docker."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from marlonthebug.core.scope import ScopeGuard, scope_from_workspace
from marlonthebug.db.models import ExploitRunModel, FindingModel
from marlonthebug.db.repository import Repository
from marlonthebug.exploit.trace import TraceRecorder, reset_trace, set_trace
from marlonthebug.exploit.webapp.utils import endpoint_candidates, is_edge_error
from marlonthebug.paths import AppPaths, package_dir
from marlonthebug.services.evidence import build_justification, extract_highlights, finalize_evidence
from marlonthebug.services.exploitation import CONFIRMATION_WORDS, ExploitBlocked
from marlonthebug.settings import AppSettings
from marlonthebug.tools.catalog import build_command, tool_by_key, tools_for_plugin
from marlonthebug.tools.docker_runner import docker_build_command, docker_url
from marlonthebug.tools.runner_factory import ToolRunner, build_tool_runner

logger = logging.getLogger("marlonthebug.tools")


class ToolService:
    def __init__(self, repository: Repository, settings: AppSettings, paths: AppPaths) -> None:
        self.repository = repository
        self.settings = settings
        self.paths = paths
        self.runner: ToolRunner = build_tool_runner(settings.tools)
        self._status_cache: dict[str, Any] | None = None
        self._status_at: float = 0.0

    @property
    def backend(self) -> str:
        return self.settings.tools.backend

    def configure(self, settings: AppSettings) -> None:
        """Rebuild the runner after a settings change from the panel."""
        self.settings = settings
        self.runner = build_tool_runner(settings.tools)
        self._status_cache = None
        self._status_at = 0.0

    async def status(self) -> dict[str, Any]:
        import time

        if self._status_cache is not None and time.monotonic() - self._status_at < 15:
            return self._status_cache
        self._status_cache = await self.runner.status()
        self._status_at = time.monotonic()
        return self._status_cache

    def available_tools(self, finding: FindingModel) -> list[dict[str, Any]]:
        if not self.settings.tools.enabled:
            return []
        return [
            {
                "key": tool.key,
                "name": tool.name,
                "description": tool.description,
                "risk": tool.risk,
            }
            for tool in tools_for_plugin(finding.plugin_name)
        ]

    async def run(
        self,
        finding_id: str,
        tool_key: str,
        confirm_text: str,
        operator: str = "panel",
    ) -> ExploitRunModel:
        finding = await self.repository.get_finding(finding_id)
        if not finding:
            raise ExploitBlocked("Hallazgo no encontrado")
        workspace = finding.workspace
        if not workspace:
            raise ExploitBlocked("El hallazgo no pertenece a un proyecto")
        if not workspace.allow_exploitation:
            raise ExploitBlocked("La explotación está desactivada en este proyecto")
        if finding.status == "false_positive":
            raise ExploitBlocked("No se puede explotar un hallazgo marcado como falso positivo")
        if confirm_text.strip().upper() not in CONFIRMATION_WORDS:
            raise ExploitBlocked("Escribe EXPLOTAR para confirmar la ejecución")
        tool = tool_by_key(tool_key)
        if not tool:
            raise ExploitBlocked(f"Herramienta no encontrada: {tool_key}")
        if finding.plugin_name not in tool.plugins:
            raise ExploitBlocked("La herramienta no corresponde al plugin del hallazgo")

        target_url, args = build_command(tool, finding)
        if not target_url:
            raise ExploitBlocked("El hallazgo no tiene endpoint ni objetivo")
        scope = scope_from_workspace(
            workspace.scope or {},
            allow_exploitation=workspace.allow_exploitation,
            require_confirmation=workspace.require_confirmation,
        )
        guard = ScopeGuard(scope)
        if not scope.is_url_allowed(target_url):
            guard.require(target_url)
        requested_url = target_url
        resolved_url = await self._resolve_url(target_url)
        if resolved_url != target_url:
            args = [item.replace(target_url, resolved_url) for item in args]
            target_url = resolved_url
        if self.settings.tools.backend in {"docker", "remote"} and self.settings.tools.rewrite_localhost:
            reachable_url = docker_url(target_url)
            if reachable_url != target_url:
                args = [item.replace(target_url, reachable_url) for item in args]
            target_url = reachable_url

        backend = self.settings.tools.backend
        runner_meta: dict[str, Any] = {
            "backend": backend,
            "operator": operator,
            "workspace": workspace.name,
            "finding_id": finding.id,
            "tool": tool.key,
        }
        if backend == "docker":
            runner_meta["image"] = self.settings.tools.docker_image
        elif backend == "remote":
            runner_meta["runner"] = self.settings.tools.remote_url
        recorder = TraceRecorder(metadata=runner_meta)
        recorder.note(
            "authorization",
            "Herramienta autorizada por el operador y el alcance del proyecto",
            {"workspace": workspace.name, "confirmation": "EXPLOTAR", "target": target_url},
        )
        recorder.note(
            "preflight",
            "Resolución de URL y preparación del motor de herramientas",
            {
                "requested": requested_url,
                "resolved": target_url,
                **({"docker_image": self.settings.tools.docker_image} if backend == "docker" else {}),
                **({"runner": self.settings.tools.remote_url} if backend == "remote" else {}),
            },
        )
        token = set_trace(recorder)
        run = await self.repository.create_exploit_run(
            workspace_id=workspace.id,
            finding_id=finding.id,
            target_id=finding.target_id,
            module_name=f"{backend}/{tool.key}",
            module_category=backend,
            risk=tool.risk,
            payload={"tool": tool.key, "target": target_url, "args": args, "backend": backend},
            operator=operator,
        )
        await self.repository.update_exploit_run(run.id, status="running", started_at=datetime.now(UTC))
        await self.repository.log_action(
            "tool.start",
            actor=operator,
            target=finding.target_host,
            detail={"finding_id": finding.id, "tool": tool.key},
        )
        try:
            result = await self.runner.run(tool.key, args, target_url, tty=tool.needs_tty)
            status = "success" if result.success else "failed"
            recorder.steps.append(
                {
                    "index": len(recorder.steps) + 1,
                    "phase": "tool",
                    "backend": backend,
                    "at": datetime.now(UTC).isoformat(),
                    "tool": tool.key,
                    "command": " ".join(result.command),
                    "returncode": result.evidence.get("returncode"),
                    "duration": result.duration,
                    "message": result.evidence.get("classification", ""),
                }
            )
            recorder.note("result", f"Resultado de la herramienta: {status}", {"success": result.success})
            tool_evidence = result.evidence
            if "highlights" not in tool_evidence:
                tool_evidence = {**tool_evidence, "highlights": extract_highlights(tool_evidence)}
            evidence = finalize_evidence(
                tool_evidence,
                build_justification(
                    finding=finding,
                    module_key=f"{backend}/{tool.key}",
                    risk=tool.risk,
                    status=status,
                    trace_steps=recorder.steps,
                    output=result.output or result.error,
                    operator=operator,
                    workspace=workspace,
                ),
                recorder.steps,
            )
            await self.repository.update_exploit_run(
                run.id,
                status=status,
                output=result.output,
                evidence=evidence,
                error=result.error,
                finished_at=datetime.now(UTC),
                cleanup_status="container_removed" if backend == "docker" else "workspace_removed",
            )
            if result.success:
                await self.repository.update_finding(
                    finding.id,
                    status="confirmed",
                    verified=True,
                    intel={
                        **(finding.intel or {}),
                        "tool": {"name": tool.key, "run_id": run.id, "backend": backend},
                    },
                )
            await self.repository.log_action(
                "tool.finish",
                actor=operator,
                target=finding.target_host,
                detail={"finding_id": finding.id, "tool": tool.key, "status": status},
            )
        except Exception as exc:
            logger.exception("Tool execution failed for finding %s", finding.id)
            recorder.note("error", str(exc))
            evidence = finalize_evidence(
                {"error": str(exc)},
                build_justification(
                    finding=finding,
                    module_key=f"{backend}/{tool.key}",
                    risk=tool.risk,
                    status="failed",
                    trace_steps=recorder.steps,
                    output=str(exc),
                    operator=operator,
                    workspace=workspace,
                ),
                recorder.steps,
            )
            await self.repository.update_exploit_run(
                run.id,
                status="failed",
                error=str(exc),
                evidence=evidence,
                finished_at=datetime.now(UTC),
            )
        finally:
            reset_trace(token)
        return await self.repository.get_exploit_run(run.id) or run

    async def _resolve_url(self, url: str) -> str:
        import httpx

        fallback = url
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
            for candidate in endpoint_candidates(url):
                fallback = candidate
                try:
                    response = await client.get(candidate)
                except Exception:
                    continue
                edge = is_edge_error(response) or any(
                    marker in response.text.lower()
                    for marker in ("ssl handshake failed", "cloudflare", "origin is unreachable")
                )
                if not edge:
                    return candidate
        return fallback

    async def build_image(self) -> tuple[int, str]:
        if self.settings.tools.backend != "docker":
            return 2, "La construcción de imagen solo aplica al backend docker"
        context = package_dir().parent
        command = docker_build_command(self.settings.tools.docker_image, context)
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await proc.communicate()
        return proc.returncode or 0, output.decode("utf-8", errors="replace")

    def build_image_sync(self) -> tuple[int, str]:
        if self.settings.tools.backend != "docker":
            return 2, "La construcción de imagen solo aplica al backend docker"
        context = Path(__file__).resolve().parents[2]
        command = docker_build_command(self.settings.tools.docker_image, context)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.returncode, (result.stdout or "") + (result.stderr or "")
