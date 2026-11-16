"""Catalog of real security tools executed inside Docker."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ToolSpec:
    key: str
    name: str
    description: str
    risk: str
    plugins: tuple[str, ...]
    build_args: Callable[[str, Any], list[str]]
    needs_tty: bool = False


def _base_url(finding: Any) -> str:
    endpoint = str(getattr(finding, "endpoint", "") or "")
    if endpoint:
        return endpoint
    target = getattr(finding, "target", None)
    host = getattr(target, "host", "") if target else ""
    return f"https://{host}" if host else ""


def _host(finding: Any) -> str:
    target = getattr(finding, "target", None)
    host = getattr(target, "host", "") if target else ""
    if host:
        return host
    parsed = urlparse(_base_url(finding))
    return parsed.hostname or ""


def _sqlmap(url: str, finding: Any) -> list[str]:
    return [
        "sqlmap",
        "-u",
        url,
        "--batch",
        "--level=3",
        "--risk=1",
        "--dbs",
        "--threads=4",
        "--timeout=10",
        "--retries=1",
        "--flush-session",
        "--output-dir=.",
    ]


def _nuclei(url: str, finding: Any) -> list[str]:
    plugin = str(getattr(finding, "plugin_name", "") or "")
    args = [
        "nuclei",
        "-u",
        url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-timeout",
        "10",
        "-retries",
        "1",
        "-severity",
        "critical,high,medium",
    ]
    tag = {
        "xss": "xss",
        "ssrf": "ssrf",
        "lfi_rfi": "lfi",
        "path_traversal": "lfi",
        "ssti": "ssti",
        "open_redirect": "redirect",
        "rce": "rce",
        "command_injection": "rce",
        "sqli": "sqli",
    }.get(plugin)
    if tag:
        args += ["-tags", tag]
    return args


def _commix(url: str, finding: Any) -> list[str]:
    return [
        "commix",
        f"--url={url}",
        "--batch",
        "--level=1",
        "--os-cmd=id",
        "--timeout=30",
    ]


def _whatweb(url: str, finding: Any) -> list[str]:
    return ["whatweb", url, "--no-errors", "--color=never"]


def _nikto(url: str, finding: Any) -> list[str]:
    return ["nikto", "-h", url, "-maxtime", "60s", "-nointeractive"]


def _nmap(url: str, finding: Any) -> list[str]:
    return ["nmap", "-Pn", "-sV", "--top-ports", "100", "-T4", _host(finding)]


def _ffuf(url: str, finding: Any) -> list[str]:
    parsed = urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else url.rstrip("/")
    target = f"{root}/FUZZ"
    return [
        "ffuf",
        "-u",
        target,
        "-w",
        "/opt/mtb/wordlists/common.txt",
        "-mc",
        "200,204,301,302,307,401,403",
        "-t",
        "10",
        "-rate",
        "10",
        "-timeout",
        "10",
        "-s",
        "-ac",
        "-H",
        "User-Agent: MarlonTheBug/2.0 (authorized security assessment)",
    ]


TOOLS: dict[str, ToolSpec] = {
    "sqlmap": ToolSpec(
        key="sqlmap",
        name="sqlmap",
        description="Detección y enumeración de bases de datos SQL con sqlmap.",
        risk="medium",
        plugins=("sqli",),
        build_args=_sqlmap,
    ),
    "nuclei": ToolSpec(
        key="nuclei",
        name="Nuclei",
        description="Motor de plantillas de vulnerabilidades de ProjectDiscovery.",
        risk="medium",
        plugins=(
            "xss",
            "ssrf",
            "lfi_rfi",
            "path_traversal",
            "ssti",
            "open_redirect",
            "rce",
            "command_injection",
            "sqli",
        ),
        build_args=_nuclei,
    ),
    "commix": ToolSpec(
        key="commix",
        name="Commix",
        description="Explotación de command injection con prueba de comando segura.",
        risk="high",
        plugins=("rce", "command_injection"),
        build_args=_commix,
        needs_tty=True,
    ),
    "whatweb": ToolSpec(
        key="whatweb",
        name="WhatWeb",
        description="Fingerprinting de tecnologías web.",
        risk="low",
        plugins=("tech_fingerprint",),
        build_args=_whatweb,
    ),
    "nikto": ToolSpec(
        key="nikto",
        name="Nikto",
        description="Escaneo de configuraciones y ficheros peligrosos.",
        risk="medium",
        plugins=("tech_fingerprint", "endpoint_discovery", "cloud_dashboards"),
        build_args=_nikto,
    ),
    "nmap": ToolSpec(
        key="nmap",
        name="Nmap",
        description="Descubrimiento de servicios y versiones en el objetivo.",
        risk="medium",
        plugins=("tech_fingerprint", "cloud_dashboards"),
        build_args=_nmap,
    ),
    "ffuf": ToolSpec(
        key="ffuf",
        name="ffuf",
        description="Descubrimiento de rutas y endpoints con wordlist integrada.",
        risk="low",
        plugins=("endpoint_discovery", "openapi", "tech_fingerprint"),
        build_args=_ffuf,
    ),
}


def tools_for_plugin(plugin_name: str) -> list[ToolSpec]:
    return [tool for tool in TOOLS.values() if plugin_name in tool.plugins]


def tool_by_key(key: str) -> ToolSpec | None:
    return TOOLS.get(key)


def build_command(tool: ToolSpec, finding: Any) -> tuple[str, list[str]]:
    url = _base_url(finding)
    return url, tool.build_args(url, finding)
