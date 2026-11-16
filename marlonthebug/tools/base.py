"""Shared result types and output helpers for tool runners."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass
class ToolResult:
    """Normalized result returned by every tool backend."""

    tool: str
    success: bool
    output: str
    evidence: dict[str, Any]
    error: str = ""
    duration: float = 0.0
    command: list[str] = field(default_factory=list)


def clean_output(value: str) -> str:
    """Strip ANSI escapes and normalize terminal line endings."""
    return ANSI_RE.sub("", value.replace("\r\n", "\n").replace("\r", "\n")).strip()


def truncate_output(value: str, limit: int) -> str:
    if limit <= 0 or len(value) <= limit:
        return value
    return value[:limit] + "\n… [salida truncada]"


def classify_output(tool: str, output: str) -> tuple[bool, str]:
    """Decide whether the tool output proves the finding.

    The runner returns raw output; classification lives on the panel so every
    backend applies exactly the same evidence rules.
    """
    lowered = output.lower()
    if tool == "sqlmap":
        if (
            "is vulnerable" in lowered
            or "available databases" in lowered
            or re.search(r"parameter:\s+\S+\s+\(", lowered)
            or "back-end dbms" in lowered
        ):
            return True, "sqlmap identificó el parámetro como inyectable"
        if "not injectable" in lowered or "does not seem to be injectable" in lowered:
            return False, "sqlmap no confirmó inyección"
    elif tool == "nuclei":
        if any(marker in lowered for marker in ('"template-id"', "[critical]", "[high]", "[medium]")):
            return True, "nuclei devolvió al menos una coincidencia"
        return False, "nuclei no devolvió coincidencias"
    elif tool == "commix":
        if "not reachable" in lowered or "does not seem" in lowered or "not injectable" in lowered:
            return False, "commix no pudo alcanzar o confirmar el objetivo"
        if (
            re.search(r"(parameter|injection point).{0,120}(vulnerable|injectable)", lowered)
            or "uid=" in lowered
            or "root:x:0:0" in lowered
            or "command execution" in lowered
        ):
            return True, "commix identificó y verificó command injection"
        return False, "commix no devolvió una confirmación de inyección"
    if tool in {"whatweb", "nikto", "nmap", "ffuf"}:
        return True, "herramienta ejecutada; revisa la salida"
    return False, "sin marcador de confirmación"


def extract_output_highlights(output: str, limit: int = 25) -> list[str]:
    markers = (
        "vulnerable",
        "injectable",
        "payload",
        "uid=",
        "gid=",
        "available databases",
        "database:",
        "back-end dbms",
        "[critical]",
        "[high]",
        "[medium]",
        "template-id",
        "root:x:0:0",
        "command execution",
        "[+]",
        "[success]",
        "[200 ok]",
        "title[",
        "ip[",
        "server[",
        "country[",
        "x-powered-by",
        "open",
    )
    highlights: list[str] = []
    for line in output.splitlines():
        clean = line.strip()
        if not clean or len(clean) < 8:
            continue
        if any(marker in clean.lower() for marker in markers) and clean not in highlights:
            highlights.append(clean[:500])
        if len(highlights) >= limit:
            break
    return highlights
