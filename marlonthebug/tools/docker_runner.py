"""Docker execution for real security tools."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from marlonthebug.settings import ToolSettings

logger = logging.getLogger("marlonthebug.tools.docker")

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass
class ToolResult:
    tool: str
    success: bool
    output: str
    evidence: dict
    error: str = ""
    duration: float = 0.0
    command: list[str] = field(default_factory=list)


class DockerToolRunner:
    def __init__(self, settings: ToolSettings) -> None:
        self.settings = settings

    async def status(self) -> dict:
        docker = shutil.which("docker")
        if not docker:
            return {
                "available": False,
                "reason": "docker no está instalado en PATH",
                "image": self.settings.docker_image,
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
                    "reason": output[:300] or "Docker daemon no disponible",
                    "image": self.settings.docker_image,
                }
            image = await self._image_exists(docker)
            return {
                "available": True,
                "version": stdout.decode("utf-8", errors="replace").strip(),
                "image": self.settings.docker_image,
                "image_ready": image,
            }
        except Exception as exc:
            return {"available": False, "reason": str(exc), "image": self.settings.docker_image}

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

    async def run(self, tool: str, args: list[str], target_url: str) -> ToolResult:
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
                {"image": self.settings.docker_image},
                error=(f"La imagen {self.settings.docker_image} no existe. Constrúyela con: marlonthebug tools build"),
            )

        container_name = f"mtb-tool-{uuid.uuid4().hex[:10]}"
        workdir = tempfile.mkdtemp(prefix="mtb-tool-")
        command = [docker, "run", "--rm", "--name", container_name, "--network", self.settings.network]
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
                    {"command": command, "target": target_url, "timeout": self.settings.timeout},
                    error=f"Tiempo máximo de {self.settings.timeout}s excedido",
                    duration=time.monotonic() - started,
                    command=command,
                )
            duration = time.monotonic() - started
            stdout_text = _clean(stdout.decode("utf-8", errors="replace"))
            stderr_text = _clean(stderr.decode("utf-8", errors="replace"))
            output = (stdout_text + ("\n" + stderr_text if stderr_text else "")).strip()
            if len(output) > self.settings.max_output_chars:
                output = output[: self.settings.max_output_chars] + "\n… [salida truncada]"
            success, reason = self._classify(tool, output)
            return ToolResult(
                tool=tool,
                success=success,
                output=output,
                evidence={
                    "tool": tool,
                    "target": target_url,
                    "command": command,
                    "returncode": proc.returncode,
                    "duration": round(duration, 2),
                    "classification": reason,
                    "output_file": f"{workdir}",
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
                {"command": command, "target": target_url},
                error=str(exc),
                duration=time.monotonic() - started,
                command=command,
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _classify(tool: str, output: str) -> tuple[bool, str]:
        lowered = output.lower()
        if tool == "sqlmap":
            if "is vulnerable" in lowered or "available databases" in lowered or "parameter:" in lowered:
                return True, "sqlmap identificó el parámetro como inyectable"
            if "not injectable" in lowered or "does not seem to be injectable" in lowered:
                return False, "sqlmap no confirmó inyección"
        elif tool == "nuclei":
            if any(marker in lowered for marker in ('"template-id"', "[critical]", "[high]", "[medium]")):
                return True, "nuclei devolvió al menos una coincidencia"
            return False, "nuclei no devolvió coincidencias"
        elif tool == "commix":
            if "vulnerable" in lowered or "injection" in lowered:
                return True, "commix identificó command injection"
            return False, "commix no confirmó command injection"
        if tool in {"whatweb", "nikto", "nmap"}:
            return True, "herramienta ejecutada; revisa la salida"
        return False, "sin marcador de confirmación"


def _clean(value: str) -> str:
    return ANSI_RE.sub("", value).strip()


def docker_url(url: str) -> str:
    """Rewrite localhost targets so Docker Desktop containers can reach them."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"host.docker.internal{port}"
        return urlunparse(parsed._replace(netloc=netloc))
    return url


def docker_build_command(image: str, context: Path) -> list[str]:
    return ["docker", "build", "-f", str(context / "Dockerfile.tools"), "-t", image, str(context)]
