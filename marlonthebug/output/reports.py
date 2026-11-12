"""Report generator — aggregates findings and renders templates."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from marlonthebug.plugins.base import Finding

logger = logging.getLogger("marlonthebug.output")


class ReportGenerator:
    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json(
        self,
        findings: list[Finding],
        workspace_name: str = "",
        filename: str | None = None,
    ) -> Path:
        filename = filename or f"{workspace_name}_report_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.json"
        filepath = self.output_dir / filename
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "workspace": workspace_name,
            "total_findings": len(findings),
            "by_severity": self._count_by_severity(findings),
            "findings": [f.to_dict() for f in findings],
        }
        filepath.write_text(json.dumps(data, indent=2))
        logger.info("JSON report saved to %s", filepath)
        return filepath

    def generate_markdown(
        self,
        findings: list[Finding],
        workspace_name: str = "",
        filename: str | None = None,
    ) -> Path:
        filename = filename or f"{workspace_name}_report_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.md"
        filepath = self.output_dir / filename

        lines: list[str] = []
        lines.append(f"# MarlonTheBug — Security Audit Report")
        lines.append(f"")
        lines.append(f"**Workspace:** {workspace_name}")
        lines.append(f"**Generated:** {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append(f"")
        lines.append(f"## Executive Summary")
        lines.append(f"")
        severity_counts = self._count_by_severity(findings)
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.title()}:** {count}")
        lines.append(f"")
        lines.append(f"## Findings")
        lines.append(f"")

        for i, finding in enumerate(sorted(findings, key=lambda f: f.cvss_score, reverse=True)):
            lines.append(f"### {i + 1}. {finding.title}")
            lines.append(f"")
            lines.append(f"| Attribute | Value |")
            lines.append(f"|-----------|-------|")
            lines.append(f"| **Severity** | {finding.severity.value.upper()} |")
            lines.append(f"| **CVSS Score** | {finding.cvss_score} |")
            lines.append(f"| **CVSS Vector** | {finding.cvss_vector} |")
            lines.append(f"| **Endpoint** | {finding.endpoint} |")
            lines.append(f"| **Target** | {finding.target_host} |")
            lines.append(f"| **Plugin** | {finding.plugin_name} |")
            lines.append(f"")
            lines.append(f"**Description:** {finding.description}")
            lines.append(f"")
            if finding.evidence:
                lines.append(f"**Evidence:**")
                lines.append(f"```json")
                lines.append(json.dumps(finding.evidence, indent=2))
                lines.append(f"```")
                lines.append(f"")
            if finding.remediation:
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append(f"")
            if finding.references:
                lines.append(f"**References:**")
                for ref in finding.references:
                    lines.append(f"- {ref}")
                lines.append(f"")
            if finding.waf_rules:
                lines.append(f"**WAF Rules:**")
                for rule in finding.waf_rules:
                    lines.append(f"```\n{rule}\n```")
                lines.append(f"")

        filepath.write_text("\n".join(lines))
        logger.info("Markdown report saved to %s", filepath)
        return filepath

    def generate_html(
        self,
        findings: list[Finding],
        workspace_name: str = "",
        filename: str | None = None,
    ) -> Path:
        try:
            from jinja2 import Template
        except ImportError:
            logger.warning("Jinja2 not available, falling back to markdown")
            return self.generate_markdown(findings, workspace_name, filename)

        filename = filename or f"{workspace_name}_report_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.html"
        filepath = self.output_dir / filename

        template = Template(HTML_TEMPLATE)
        rendered = template.render(
            workspace=workspace_name,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            total=len(findings),
            severity_counts=self._count_by_severity(findings),
            findings=sorted(findings, key=lambda f: f.cvss_score, reverse=True),
        )
        filepath.write_text(rendered)
        logger.info("HTML report saved to %s", filepath)
        return filepath

    @staticmethod
    def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MarlonTheBug — Security Audit Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               max-width: 960px; margin: 0 auto; padding: 2rem;
               background: #1a1a2e; color: #e0e0e0; }
        h1 { color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 0.5rem; }
        h2 { color: #0f3460; margin-top: 2rem; }
        h3 { color: #16213e; }
        .finding { background: #16213e; border-radius: 8px; padding: 1.5rem; margin: 1rem 0;
                   border-left: 4px solid #e94560; }
        .critical { border-left-color: #ff0000; }
        .high { border-left-color: #ff6600; }
        .medium { border-left-color: #ffcc00; }
        .low { border-left-color: #3399ff; }
        .info { border-left-color: #999999; }
        .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
                 font-size: 0.85rem; font-weight: bold; }
        .badge-critical { background: #ff0000; color: white; }
        .badge-high { background: #ff6600; color: white; }
        .badge-medium { background: #ffcc00; color: #333; }
        .badge-low { background: #3399ff; color: white; }
        .badge-info { background: #999999; color: white; }
        table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
        th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #333; }
        pre { background: #0d1117; padding: 1rem; border-radius: 4px; overflow-x: auto; }
        code { font-family: 'Fira Code', monospace; }
    </style>
</head>
<body>
    <h1>MarlonTheBug — Security Audit Report</h1>
    <p><strong>Workspace:</strong> {{ workspace }}</p>
    <p><strong>Generated:</strong> {{ generated_at }}</p>
    <p><strong>Total Findings:</strong> {{ total }}</p>

    <h2>Executive Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        {% for sev in ['critical', 'high', 'medium', 'low', 'info'] %}
        {% set count = severity_counts.get(sev, 0) %}
        {% if count > 0 %}
        <tr><td><span class="badge badge-{{ sev }}">{{ sev.upper() }}</span></td><td>{{ count }}</td></tr>
        {% endif %}
        {% endfor %}
    </table>

    <h2>Findings</h2>
    {% for finding in findings %}
    <div class="finding {{ finding.severity.value }}">
        <h3><span class="badge badge-{{ finding.severity.value }}">{{ finding.severity.value.upper() }}</span> {{ finding.title }}</h3>
        <table>
            <tr><td><strong>CVSS Score</strong></td><td>{{ finding.cvss_score }}</td></tr>
            <tr><td><strong>Endpoint</strong></td><td>{{ finding.endpoint }}</td></tr>
            <tr><td><strong>Target</strong></td><td>{{ finding.target_host }}</td></tr>
            <tr><td><strong>Plugin</strong></td><td>{{ finding.plugin_name }}</td></tr>
        </table>
        <p><strong>Description:</strong></p>
        <p>{{ finding.description }}</p>
        {% if finding.evidence %}
        <p><strong>Evidence:</strong></p>
        <pre><code>{{ finding.evidence | tojson(indent=2) }}</code></pre>
        {% endif %}
        {% if finding.remediation %}
        <p><strong>Remediation:</strong></p>
        <p>{{ finding.remediation }}</p>
        {% endif %}
        {% if finding.references %}
        <p><strong>References:</strong></p>
        <ul>{% for ref in finding.references %}<li>{{ ref }}</li>{% endfor %}</ul>
        {% endif %}
        {% if finding.waf_rules %}
        <p><strong>WAF Rules:</strong></p>
        {% for rule in finding.waf_rules %}<pre><code>{{ rule }}</code></pre>{% endfor %}
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>"""
