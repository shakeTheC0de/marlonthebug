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
from marlonthebug.exploit.webapp.utils import endpoint_candidates, is_edge_error
from marlonthebug.paths import AppPaths, package_dir
from marlonthebug.services.exploitation import CONFIRMATION_WORDS, ExploitBlocked
from marlonthebug.settings import AppSettings
from marlonthebug.tools.catalog import build_command, tool_by_key, tools_for_plugin
from marlonthebug.tools.docker_runner import DockerToolRunner, docker_build_command, docker_url

logger = logging.getLogger("marlonthebug.tools")


class ToolService:
    def __init__(self, repository: Repository, settings: AppSettings, paths: AppPaths) -> None:
        self.repository = repository
        self.settings = settings
        self.paths = paths
        self.runner = DockerToolRunner(settings.tools)
        self._status_cache: dict[str, Any] | None = None
        self._status_at: float = 0.0

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
        resolved_url = await self._resolve_url(target_url)
        if resolved_url != target_url:
            args = [item.replace(target_url, resolved_url) for item in args]
            target_url = resolved_url
        container_url = docker_url(target_url)
        if container_url != target_url:
            args = [
                item.replace(target_url, container_url)
                .replace("127.0.0.1", "host.docker.internal")
                .replace("localhost", "host.docker.internal")
                for item in args
            ]
        target_url = container_url

        run = await self.repository.create_exploit_run(
            workspace_id=workspace.id,
            finding_id=finding.id,
            target_id=finding.target_id,
            module_name=f"docker/{tool.key}",
            module_category="docker",
            risk=tool.risk,
            payload={"tool": tool.key, "target": target_url, "args": args},
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
            result = await self.runner.run(tool.key, args, target_url)
            status = "success" if result.success else "failed"
            await self.repository.update_exploit_run(
                run.id,
                status=status,
                output=result.output,
                evidence=result.evidence,
                error=result.error,
                finished_at=datetime.now(UTC),
                cleanup_status="container_removed",
            )
            if result.success:
                await self.repository.update_finding(
                    finding.id,
                    status="confirmed",
                    verified=True,
                    intel={
                        **(finding.intel or {}),
                        "tool": {"name": tool.key, "run_id": run.id, "image": self.settings.tools.docker_image},
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
            await self.repository.update_exploit_run(
                run.id,
                status="failed",
                error=str(exc),
                finished_at=datetime.now(UTC),
            )
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
        context = Path(__file__).resolve().parents[2]
        command = docker_build_command(self.settings.tools.docker_image, context)
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.returncode, (result.stdout or "") + (result.stderr or "")
