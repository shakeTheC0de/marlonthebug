"""Orchestration engine — manages workspace lifecycle, plugin execution, and scan coordination."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from marlonthebug.core.events import EventBus
from marlonthebug.core.pipeline import Pipeline, PipelineStage
from marlonthebug.core.scheduler import Scheduler
from marlonthebug.core.workspace import WorkspaceManager

if TYPE_CHECKING:
    from marlonthebug.plugins.base import BasePlugin

logger = logging.getLogger("marlonthebug.engine")


@dataclass
class EngineConfig:
    threads: int = 50
    timeout: int = 10
    retries: int = 3
    verify_ssl: bool = True
    follow_redirects: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@dataclass
class ScanResult:
    workspace_name: str
    pipeline: Pipeline
    duration: float = 0.0
    findings: list[Any] = field(default_factory=list)


class Engine:
    def __init__(
        self,
        workspaces_dir: Path | None = None,
        config: EngineConfig | None = None,
        auto_discover: bool = True,
    ) -> None:
        self.event_bus = EventBus()
        self.config = config or EngineConfig()
        self.scheduler = Scheduler(max_concurrent=self.config.threads)
        self.workspace_manager = WorkspaceManager(
            base_dir=workspaces_dir or Path("workspaces"),
            event_bus=self.event_bus,
        )
        self._plugin_registry: dict[str, BasePlugin] = {}
        self._running = False

        if auto_discover:
            self._discover_plugins()

    def register_plugin(self, plugin: "BasePlugin") -> None:
        key = f"{plugin.category}/{plugin.name}"
        self._plugin_registry[key] = plugin
        logger.debug("Registered plugin: %s", key)

    def _discover_plugins(self) -> None:
        from marlonthebug.plugins.registry import PluginRegistry

        registry = PluginRegistry()
        registry.discover()
        for _key, instance in registry._instances.items():
            self._plugin_registry[_key] = instance
        logger.info("Auto-discovered %d plugins", len(self._plugin_registry))

    def get_plugin(self, category: str, name: str) -> "BasePlugin | None":
        return self._plugin_registry.get(f"{category}/{name}")

    def get_plugins_by_category(self, category: str) -> list["BasePlugin"]:
        return [p for k, p in self._plugin_registry.items() if k.startswith(f"{category}/")]

    def list_plugins(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for _key, plugin in self._plugin_registry.items():
            category = plugin.category
            if category not in result:
                result[category] = []
            result[category].append(plugin.name)
        return result

    async def start(self) -> None:
        self._running = True
        await self.event_bus.start()
        logger.info("Engine started")

    async def stop(self) -> None:
        self._running = False
        await self.event_bus.stop()
        self.scheduler.cancel_all()
        logger.info("Engine stopped")

    async def run_recon(
        self,
        targets: list[Any],
        options: dict[str, Any] | None = None,
    ) -> list[Any]:
        workspace = self.workspace_manager.current
        if not workspace:
            raise RuntimeError("No active workspace")

        plugins = self.get_plugins_by_category("recon")
        if not plugins:
            logger.warning("No recon plugins registered")
            return []

        pipeline = Pipeline(workspace=workspace, event_bus=self.event_bus)
        findings: list[Any] = []

        async for finding in pipeline.run_stage(PipelineStage.RECON, plugins, targets, options):
            findings.append(finding)

        logger.info("Recon complete: %d findings", len(findings))
        return findings

    async def run_audit(
        self,
        targets: list[Any],
        categories: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> list[Any]:
        workspace = self.workspace_manager.current
        if not workspace:
            raise RuntimeError("No active workspace")

        categories = categories or ["web", "api", "auth"]
        plugins: list[Any] = []
        for cat in categories:
            plugins.extend(self.get_plugins_by_category(cat))

        if not plugins:
            logger.warning("No audit plugins registered for categories: %s", categories)
            return []

        pipeline = Pipeline(workspace=workspace, event_bus=self.event_bus)
        findings: list[Any] = []

        async for finding in pipeline.run_stage(PipelineStage.AUDIT, plugins, targets, options):
            findings.append(finding)

        logger.info("Audit complete: %d findings", len(findings))
        return findings

    async def run_full(
        self,
        targets: list[Any],
        options: dict[str, Any] | None = None,
    ) -> ScanResult:
        import time

        start = time.monotonic()
        workspace = self.workspace_manager.current
        if not workspace:
            raise RuntimeError("No active workspace")

        pipeline = Pipeline(workspace=workspace, event_bus=self.event_bus)
        all_findings: list[Any] = []

        async for finding in pipeline.run_stage(
            PipelineStage.RECON,
            self.get_plugins_by_category("recon"),
            targets,
            options,
        ):
            all_findings.append(finding)

        async for finding in pipeline.run_stage(
            PipelineStage.AUDIT,
            self.get_plugins_by_category("web") + self.get_plugins_by_category("api"),
            targets,
            options,
        ):
            all_findings.append(finding)

        duration = time.monotonic() - start
        return ScanResult(
            workspace_name=workspace.name,
            pipeline=pipeline,
            duration=duration,
            findings=all_findings,
        )
