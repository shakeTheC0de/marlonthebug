"""Tool catalog and execution backends (docker, remote and local)."""

from marlonthebug.tools.base import ToolResult
from marlonthebug.tools.catalog import TOOLS, ToolSpec, tool_by_key, tools_for_plugin
from marlonthebug.tools.docker_runner import DockerToolRunner
from marlonthebug.tools.local_runner import LocalToolRunner
from marlonthebug.tools.remote_runner import RemoteToolRunner
from marlonthebug.tools.runner_factory import build_tool_runner
from marlonthebug.tools.service import ToolService

__all__ = [
    "TOOLS",
    "DockerToolRunner",
    "LocalToolRunner",
    "RemoteToolRunner",
    "ToolResult",
    "ToolService",
    "ToolSpec",
    "build_tool_runner",
    "tool_by_key",
    "tools_for_plugin",
]
