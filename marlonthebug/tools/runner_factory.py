"""Select the configured tool execution backend."""

from __future__ import annotations

from marlonthebug.settings import ToolSettings
from marlonthebug.tools.docker_runner import DockerToolRunner
from marlonthebug.tools.local_runner import LocalToolRunner
from marlonthebug.tools.remote_runner import RemoteToolRunner

ToolRunner = DockerToolRunner | LocalToolRunner | RemoteToolRunner


def build_tool_runner(settings: ToolSettings) -> ToolRunner:
    if settings.backend == "remote":
        return RemoteToolRunner(settings)
    if settings.backend == "local":
        return LocalToolRunner(settings)
    return DockerToolRunner(settings)
