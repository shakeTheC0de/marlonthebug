"""Professional report generation (HTML, PDF, Markdown and JSON)."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from marlonthebug.db.models import FindingModel, ReportModel, ScanRunModel
from marlonthebug.db.repository import Repository
from marlonthebug.paths import AppPaths, resource_path
from marlonthebug.settings import AppSettings

logger = logging.getLogger("marlonthebug.reports")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABELS_ES = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Informativa",
}
SEVERITY_LABELS_EN = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
}


@dataclass
class ReportRequest:
    workspace_id: str
    scan_run_id: str | None = None
    template: str = "full"
    language: str = "es"
    format: str = "pdf"
    classification: str = "CONFIDENCIAL"
    company: str = "MarlonTheBug"
    client_name: str = ""
    title: str = ""
    include_evidence: bool = True
    include_remediation: bool = True
    include_waf_rules: bool = True
    options: dict[str, Any] = field(default_factory=dict)


class ReportService:
    def __init__(self, repository: Repository, settings: AppSettings, paths: AppPaths) -> None:
        self.repository = repository
        self.settings = settings
        self.paths = paths
        self.template_dir = resource_path("output", "templates")
        self.html_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.html_env.filters["severity_label"] = self._severity_label
        self.md_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.md_env.filters["severity_label"] = self._severity_label

    def _severity_label(self, value: str, language: str = "es") -> str:
        labels = SEVERITY_LABELS_ES if language == "es" else SEVERITY_LABELS_EN
        return labels.get(value, value)

    async def build_context(self, request: ReportRequest) -> dict[str, Any]:
        workspace = await self.repository.get_workspace(request.workspace_id)
        if not workspace:
            raise ValueError("Workspace not found")
        scan = await self.repository.get_scan(request.scan_run_id) if request.scan_run_id else None
        findings = await self._findings_for(workspace.id, scan)
        findings.sort(
            key=lambda item: (
                SEVERITY_ORDER.index(item.severity) if item.severity in SEVERITY_ORDER else 5,
                -item.cvss_score,
            )
        )
        severity = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in findings:
            if finding.severity in severity:
                severity[finding.severity] += 1
        counts = {
            "total": len(findings),
            "severity": severity,
            "kev": sum(1 for finding in findings if finding.kev),
            "verified": sum(1 for finding in findings if finding.verified),
            "confirmed": sum(1 for finding in findings if finding.status == "confirmed"),
            "open": sum(1 for finding in findings if finding.status == "open"),
        }
        category_counts: dict[str, int] = {}
        for finding in findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        counts["categories"] = category_counts
        target_hosts = sorted({finding.target_host for finding in findings if finding.target_host})
        risk = self._risk_label(severity)
        feeds = await self.repository.list_feeds()
        intel_sources = [
            {
                "name": feed.name,
                "source": feed.source,
                "status": feed.status,
                "count": feed.count,
                "last_sync": feed.last_sync,
                "error": feed.error,
            }
            for feed in feeds
        ]
        return {
            "workspace": workspace,
            "scan": scan,
            "findings": findings,
            "stats": counts,
            "risk": risk,
            "target_hosts": target_hosts,
            "intel_sources": intel_sources,
            "generated_at": datetime.now(UTC),
            "generated_at_text": datetime.now(UTC).strftime("%d/%m/%Y %H:%M UTC"),
            "request": request,
            "language": request.language,
            "classification": request.classification,
            "company": request.company,
            "client_name": request.client_name or workspace.client_name or workspace.name,
            "title": request.title or f"Informe de seguridad — {workspace.name}",
            "template": request.template,
            "include_evidence": request.include_evidence,
            "include_remediation": request.include_remediation,
            "include_waf_rules": request.include_waf_rules,
            "severity_labels": SEVERITY_LABELS_ES if request.language == "es" else SEVERITY_LABELS_EN,
            "severity_order": SEVERITY_ORDER,
            "category_labels": {
                "recon": "Reconocimiento",
                "web": "Seguridad web",
                "api": "Seguridad de API",
                "auth": "Autenticación y acceso",
                "cloud": "Cloud y contenedores",
                "llm": "IA / LLM",
                "general": "General",
            },
            "status_labels": {
                "open": "Abierto",
                "confirmed": "Confirmado",
                "false_positive": "Falso positivo",
                "accepted": "Riesgo aceptado",
                "remediated": "Remediado",
            },
        }

    async def preview(self, request: ReportRequest) -> str:
        context = await self.build_context(request)
        return self.html_env.get_template("report.html").render(**context)

    async def generate(self, request: ReportRequest) -> ReportModel:
        context = await self.build_context(request)
        self.paths.reports_dir.mkdir(parents=True, exist_ok=True)
        stem = self._filename_stem(context["workspace"].name)
        requested_format = request.format.lower()

        if requested_format == "json":
            path = self.paths.reports_dir / f"{stem}.json"
            path.write_text(json.dumps(self._json_payload(context), indent=2, ensure_ascii=False), encoding="utf-8")
            actual_format = "json"
        elif requested_format == "markdown" or requested_format == "md":
            path = self.paths.reports_dir / f"{stem}.md"
            path.write_text(self.md_env.get_template("report.md.j2").render(**context), encoding="utf-8")
            actual_format = "markdown"
        else:
            html = self.html_env.get_template("report.html").render(**context)
            html_path = self.paths.reports_dir / f"{stem}.html"
            html_path.write_text(html, encoding="utf-8")
            if requested_format == "pdf":
                pdf_path = self.paths.reports_dir / f"{stem}.pdf"
                if await self._render_pdf(html_path, pdf_path):
                    path = pdf_path
                    actual_format = "pdf"
                else:
                    path = html_path
                    actual_format = "html"
                    context["request"].options["pdf_fallback"] = True
                    logger.warning("PDF renderer unavailable; HTML report saved instead")
            else:
                path = html_path
                actual_format = "html"

        report = await self.repository.create_report(
            workspace_id=context["workspace"].id,
            scan_run_id=context["scan"].id if context["scan"] else None,
            name=context["title"],
            format=actual_format,
            template=request.template,
            language=request.language,
            filename=path.name,
            path=str(path),
            size=path.stat().st_size if path.exists() else 0,
            options={
                "classification": request.classification,
                "client_name": context["client_name"],
                "pdf_fallback": request.options.get("pdf_fallback", False),
            },
        )
        await self.repository.log_action(
            "report.generate",
            target=context["workspace"].name,
            detail={"report_id": report.id, "format": actual_format, "findings": len(context["findings"])},
        )
        return report

    async def _findings_for(
        self,
        workspace_id: str,
        scan: ScanRunModel | None,
    ) -> list[FindingModel]:
        findings = await self.repository.list_all_findings(workspace_id, limit=5000)
        if not scan:
            return findings
        selected = []
        for finding in findings:
            occurrences = finding.occurrences or []
            if finding.scan_run_id == scan.id or scan.id in occurrences:
                selected.append(finding)
        return selected

    async def _render_pdf(self, html_path: Path, pdf_path: Path) -> bool:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            if await self._render_pdf_chrome(html_path, pdf_path):
                return True
            return await self._render_pdf_weasyprint(html_path, pdf_path)

        try:
            async with async_playwright() as playwright:
                for channel in (None, "chrome", "msedge"):
                    try:
                        browser = (
                            await playwright.chromium.launch(channel=channel)
                            if channel
                            else await playwright.chromium.launch()
                        )
                        page = await browser.new_page()
                        await page.goto(html_path.as_uri(), wait_until="load")
                        await page.pdf(
                            path=str(pdf_path),
                            format="A4",
                            print_background=True,
                            margin={"top": "18mm", "bottom": "18mm", "left": "15mm", "right": "15mm"},
                        )
                        await browser.close()
                        return True
                    except Exception:
                        continue
        except Exception as exc:
            logger.debug("Playwright PDF failed: %s", exc)
        if await self._render_pdf_chrome(html_path, pdf_path):
            return True
        return await self._render_pdf_weasyprint(html_path, pdf_path)

    async def _render_pdf_chrome(self, html_path: Path, pdf_path: Path) -> bool:
        import asyncio

        binary = _find_chrome()
        if not binary:
            return False

        def render() -> bool:
            try:
                subprocess.run(
                    [
                        binary,
                        "--headless=new",
                        "--disable-gpu",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--no-pdf-header-footer",
                        f"--print-to-pdf={pdf_path}",
                        html_path.as_uri(),
                    ],
                    check=False,
                    timeout=90,
                    capture_output=True,
                )
                return pdf_path.exists() and pdf_path.stat().st_size > 1000
            except Exception as exc:
                logger.debug("Chrome PDF failed: %s", exc)
                return False

        return await asyncio.to_thread(render)

    async def _render_pdf_weasyprint(self, html_path: Path, pdf_path: Path) -> bool:
        try:
            from weasyprint import HTML
        except ImportError:
            return False
        try:
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            return True
        except Exception as exc:
            logger.debug("WeasyPrint PDF failed: %s", exc)
            return False

    @staticmethod
    def _filename_stem(name: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", name).strip("-").lower()
        return f"{slug or 'workspace'}-{datetime.now(UTC):%Y%m%d_%H%M%S}"

    @staticmethod
    def _risk_label(severity: dict[str, int]) -> str:
        if severity.get("critical"):
            return "CRÍTICO"
        if severity.get("high"):
            return "ALTO"
        if severity.get("medium"):
            return "MEDIO"
        if severity.get("low"):
            return "BAJO"
        return "INFORMATIVO"

    @staticmethod
    def _json_payload(context: dict[str, Any]) -> dict[str, Any]:
        return {
            "generated_at": context["generated_at"].isoformat(),
            "workspace": context["workspace"].name,
            "client": context["client_name"],
            "classification": context["classification"],
            "risk": context["risk"],
            "stats": context["stats"],
            "intel_sources": [
                {
                    **item,
                    "last_sync": item["last_sync"].isoformat() if item.get("last_sync") else "",
                }
                for item in context.get("intel_sources", [])
            ],
            "findings": [
                {
                    "plugin": finding.plugin_name,
                    "category": finding.category,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "cvss_score": finding.cvss_score,
                    "cvss_vector": finding.cvss_vector,
                    "cwe": finding.cwe,
                    "owasp": finding.owasp,
                    "endpoint": finding.endpoint,
                    "target": finding.target_host,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "references": finding.references,
                    "waf_rules": finding.waf_rules,
                    "kev": finding.kev,
                    "epss": finding.epss,
                    "verified": finding.verified,
                    "exploit_runs": [
                        {
                            "module": run.module_name,
                            "status": run.status,
                            "risk": run.risk,
                            "output": run.output[:2000],
                            "evidence": run.evidence,
                            "started_at": run.started_at.isoformat() if run.started_at else None,
                            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                        }
                        for run in (finding.exploit_runs or [])
                        if run.status == "success"
                    ],
                }
                for finding in context["findings"]
            ],
        }


def _find_chrome() -> str | None:
    candidates: list[str] = []
    if sys.platform == "darwin":
        candidates += [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    elif sys.platform.startswith("win"):
        candidates += [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ]
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return None
