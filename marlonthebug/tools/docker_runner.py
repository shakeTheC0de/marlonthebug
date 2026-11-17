"""Docker execution for real security tools."""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from marlonthebug.settings import ToolSettings
from marlonthebug.tools.base import (
    ToolResult,
    classify_output,
    clean_output,
    extract_output_highlights,
    truncate_output,
)

logger = logging.getLogger("marlonthebug.tools.docker")

__all__ = ["DockerToolRunner", "ToolResult", "docker_build_command", "docker_url"]


class DockerToolRunner:
    """Run each tool in an ephemeral, capability-restricted container."""

    backend = "docker"

    def __init__(self, settings: ToolSettings) -> None:
        self.settings = settings

    async def status(self) -> dict:
        docker = shutil.which("docker")
        if not docker:
            return {
                "available": False,
                "backend": self.backend,
                "reason": "docker no está instalado en PATH",
                "image": self.settings.docker_image,
                "image_ready": False,
            }
        try:
            proc = await asyncio.create_subprocess_exec(
                docker,
                "info",
                "--format",
                "{{.ServerVersion}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = (stdout + stderr).decode("utf-8", errors="replace")
            lowered = output.lower()
            if (
                proc.returncode != 0
                or not stdout.strip()
                or "cannot connect" in lowered
                or "is the docker daemon running" in lowered
            ):
                return {
                    "available": False,
                    "backend": self.backend,
                    "reason": output[:300] or "Docker daemon no disponible",
                    "image": self.settings.docker_image,
                    "image_ready": False,
                }
            image = await self._image_exists(docker)
            return {
                "available": True,
                "backend": self.backend,
                "version": stdout.decode("utf-8", errors="replace").strip(),
                "image": self.settings.docker_image,
                "image_ready": image,
            }
        except Exception as exc:
            return {
                "available": False,
                "backend": self.backend,
                "reason": str(exc),
                "image": self.settings.docker_image,
                "image_ready": False,
            }

    async def _image_exists(self, docker: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            docker,
            "image",
            "inspect",
            self.settings.docker_image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await proc.wait() == 0

    async def run(self, tool: str, args: list[str], target_url: str, tty: bool = False) -> ToolResult:
        if not self.settings.enabled:
            return ToolResult(tool, False, "", {}, error="Las herramientas externas están desactivadas")
        docker = shutil.which("docker")
        if not docker:
            return ToolResult(tool, False, "", {}, error="docker no está instalado")
        available = await self.status()
        if not available.get("available"):
            return ToolResult(tool, False, "", {}, error=f"Docker no disponible: {available.get('reason', '')}")
        if not available.get("image_ready"):
            return ToolResult(
                tool,
                False,
                "",
                {"image": self.settings.docker_image, "backend": self.backend},
                error=(f"La imagen {self.settings.docker_image} no existe. Constrúyela con: marlonthebug tools build"),
            )

        container_name = f"mtb-tool-{uuid.uuid4().hex[:10]}"
        workdir = tempfile.mkdtemp(prefix="mtb-tool-")
        command = [docker, "run", "--rm", "--name", container_name, "--network", self.settings.network]
        if tty:
            command.append("-t")
        if self.settings.network != "host":
            command += ["--add-host", "host.docker.internal:host-gateway"]
        command += [
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "1g",
            "--cpus",
            "1.0",
            "-v",
            f"{workdir}:/work",
            "-w",
            "/work",
            self.settings.docker_image,
            *args,
        ]
        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.settings.timeout)
            except TimeoutError:
                await asyncio.create_subprocess_exec(docker, "rm", "-f", container_name)
                return ToolResult(
                    tool,
                    False,
                    "",
                    {
                        "command": command,
                        "target": target_url,
                        "timeout": self.settings.timeout,
                        "backend": self.backend,
                    },
                    error=f"Tiempo máximo de {self.settings.timeout}s excedido",
                    duration=time.monotonic() - started,
                    command=command,
                )
            duration = time.monotonic() - started
            stdout_text = clean_output(stdout.decode("utf-8", errors="replace"))
            stderr_text = clean_output(stderr.decode("utf-8", errors="replace"))
            output = (stdout_text + ("\n" + stderr_text if stderr_text else "")).strip()
            output = truncate_output(output, self.settings.max_output_chars)
            success, reason = classify_output(tool, output)
            highlights = extract_output_highlights(output)
            return ToolResult(
                tool=tool,
                success=success,
                output=output,
                evidence={
                    "tool": tool,
                    "target": target_url,
                    "backend": self.backend,
                    "image": self.settings.docker_image,
                    "command": command,
                    "returncode": proc.returncode,
                    "duration": round(duration, 2),
                    "classification": reason,
                    "highlights": highlights,
                    "output_file": workdir,
                },
                error="" if success else reason,
                duration=duration,
                command=command,
            )
        except Exception as exc:
            return ToolResult(
                tool,
                False,
                "",
                {"command": command, "target": target_url, "backend": self.backend},
                error=str(exc),
                duration=time.monotonic() - started,
                command=command,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _classify(tool: str, output: str) -> tuple[bool, str]:
        """Backward-compatible wrapper used by older integrations."""
        return classify_output(tool, output)


def docker_url(url: str) -> str:
    """Rewrite localhost targets so Docker containers can reach the host."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"host.docker.internal{port}"
        return urlunparse(parsed._replace(netloc=netloc))
    return url


def docker_build_command(image: str, context: Path) -> list[str]:
    return ["docker", "build", "-f", str(context / "Dockerfile.tools"), "-t", image, str(context)]
