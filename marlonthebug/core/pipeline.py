"""Module pipeline — chains plugins stages: recon → audit → exploit."""

import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from marlonthebug.core.events import EventBus
    from marlonthebug.core.workspace import Workspace
    from marlonthebug.plugins.base import BasePlugin

logger = logging.getLogger("marlonthebug.pipeline")


class PipelineStage(StrEnum):
    RECON = "recon"
    AUDIT = "audit"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    REPORT = "report"


@dataclass
class PipelineResult:
    stage: PipelineStage
    plugin_name: str
    findings: list[Any] = field(default_factory=list)
    errors: list[Exception] = field(default_factory=list)
    duration: float = 0.0


class Pipeline:
    def __init__(
        self,
        workspace: "Workspace",
        event_bus: "EventBus | None" = None,
    ) -> None:
        self.workspace = workspace
        self.event_bus = event_bus
        self.results: dict[PipelineStage, list[PipelineResult]] = {stage: [] for stage in PipelineStage}

    async def run_stage(
        self,
        stage: PipelineStage,
        plugins: list["BasePlugin"],
        targets: list[Any],
        options: dict[str, Any] | None = None,
    ) -> AsyncIterator[Any]:
        import time

        options = options or {}
        stage_results: list[PipelineResult] = []

        for plugin in plugins:
            logger.info("[%s] Running %s", stage.value, plugin.name)
            start = time.monotonic()
            result = PipelineResult(stage=stage, plugin_name=plugin.name)

            try:
                await plugin.setup(self.workspace)
                for target in targets:
                    async for finding in plugin.run(target, options):
                        result.findings.append(finding)
                        if self.event_bus:
                            from marlonthebug.core.events import Event, EventType

                            await self.event_bus.emit(
                                Event(
                                    type=EventType.FINDING_CREATED,
                                    source=plugin.name,
                                    data={"finding": finding, "target": target},
                                )
                            )
                        yield finding
            except Exception as e:
                logger.exception("Pipeline error in %s/%s", stage.value, plugin.name)
                result.errors.append(e)
            finally:
                await plugin.teardown()
                result.duration = time.monotonic() - start
                stage_results.append(result)

            if self.event_bus:
                from marlonthebug.core.events import Event, EventType

                await self.event_bus.emit(
                    Event(
                        type=EventType.PLUGIN_COMPLETED,
                        source=plugin.name,
                        data={"stage": stage.value, "result": result},
                    )
                )

        self.results[stage].extend(stage_results)

    def summary(self) -> dict[str, int]:
        total_findings = 0
        total_errors = 0
        for stage_results in self.results.values():
            for r in stage_results:
                total_findings += len(r.findings)
                total_errors += len(r.errors)
        return {
            "stages_run": sum(1 for r in self.results.values() if r),
            "total_findings": total_findings,
            "total_errors": total_errors,
        }
