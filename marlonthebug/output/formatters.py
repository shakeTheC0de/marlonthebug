"""Output formatters — JSON, Markdown, HTML, PDF."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from marlonthebug.plugins.base import Finding, Severity

logger = logging.getLogger("marlonthebug.output")


class JSONFormatter:
    @staticmethod
    def format(findings: list[Finding], indent: int = 2) -> str:
        return json.dumps([f.to_dict() for f in findings], indent=indent)

    @staticmethod
    def save(findings: list[Finding], path: Path) -> Path:
        path.write_text(JSONFormatter.format(findings))
        return path


class MarkdownFormatter:
    @staticmethod
    def format_header(title: str, level: int = 1) -> str:
        return f"{'#' * level} {title}\n"

    @staticmethod
    def format_table(headers: list[str], rows: list[list[str]]) -> str:
        lines: list[str] = []
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("|" + "|".join("---" for _ in headers) + "|")
        for row in rows:
            lines.append("| " + " | ".join(str(c) for c in row) + " |")
        return "\n".join(lines)

    @staticmethod
    def severity_badge(severity: str) -> str:
        badges = {
            "critical": "🔴 **CRITICAL**",
            "high": "🟠 **HIGH**",
            "medium": "🟡 **MEDIUM**",
            "low": "🟢 **LOW**",
            "info": "⚪ **INFO**",
        }
        return badges.get(severity.lower(), severity)


class HTMLFormatter:
    @staticmethod
    def finding_card(finding: Finding) -> str:
        return f"""
<div class="finding {finding.severity.value}">
    <h3>{finding.title}</h3>
    <span class="badge badge-{finding.severity.value}">{finding.severity.value.upper()}</span>
    <p><strong>CVSS:</strong> {finding.cvss_score}</p>
    <p><strong>Endpoint:</strong> {finding.endpoint}</p>
    <p>{finding.description}</p>
    <pre><code>{json.dumps(finding.evidence, indent=2)}</code></pre>
    <p><strong>Remediation:</strong> {finding.remediation}</p>
</div>"""


def save_findings_json(findings: list[Finding], filepath: Path) -> Path:
    return JSONFormatter.save(findings, filepath)


def save_findings_markdown(findings: list[Finding], filepath: Path, title: str = "Findings") -> Path:
    lines: list[str] = []
    lines.append(f"# {title}\n")
    for f in findings:
        lines.append(f"## {f.title}")
        lines.append(f"**Severity:** {MarkdownFormatter.severity_badge(f.severity.value)}")
        lines.append(f"**CVSS Score:** {f.cvss_score}")
        lines.append(f"**Endpoint:** {f.endpoint}")
        lines.append(f"")
        lines.append(f.description)
        lines.append(f"")
        if f.remediation:
            lines.append(f"### Remediation")
            lines.append(f.remediation)
            lines.append(f"")
    filepath.write_text("\n".join(lines))
    return filepath
