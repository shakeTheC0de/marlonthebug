"""JSON serializers for the public API and HTMX-friendly responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from marlonthebug.db.models import (
    AuditLogModel,
    CveModel,
    FindingModel,
    ReportModel,
    ScanRunModel,
    TargetModel,
    WorkspaceModel,
)


def iso(value: Any) -> str | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def workspace_dict(workspace: WorkspaceModel) -> dict[str, Any]:
    return {
        "id": workspace.id,
        "name": workspace.name,
        "client_name": workspace.client_name,
        "description": workspace.description,
        "scope": workspace.scope,
        "allow_exploitation": workspace.allow_exploitation,
        "targets": len(workspace.targets or []),
        "created_at": iso(workspace.created_at),
        "updated_at": iso(workspace.updated_at),
    }


def target_dict(target: TargetModel) -> dict[str, Any]:
    return {
        "id": target.id,
        "host": target.host,
        "kind": target.kind,
        "technologies": target.technologies,
        "ports": target.ports,
        "metadata": target.metadata_,
        "first_seen": iso(target.first_seen),
        "last_seen": iso(target.last_seen),
    }


def scan_dict(scan: ScanRunModel) -> dict[str, Any]:
    return {
        "id": scan.id,
        "workspace_id": scan.workspace_id,
        "profile": scan.profile,
        "status": scan.status,
        "targets": scan.targets,
        "categories": scan.categories,
        "modules": scan.modules,
        "stats": scan.stats,
        "error": scan.error,
        "created_at": iso(scan.created_at),
        "started_at": iso(scan.started_at),
        "finished_at": iso(scan.finished_at),
    }


def finding_dict(finding: FindingModel, include_evidence: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": finding.id,
        "workspace_id": finding.workspace_id,
        "scan_run_id": finding.scan_run_id,
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
        "remediation": finding.remediation,
        "references": finding.references,
        "kev": finding.kev,
        "epss": finding.epss,
        "verified": finding.verified,
        "notes": finding.notes,
        "fingerprint": finding.fingerprint,
        "first_seen": iso(finding.first_seen),
        "last_seen": iso(finding.last_seen),
        "created_at": iso(finding.created_at),
    }
    if include_evidence:
        data["evidence"] = finding.evidence
        data["waf_rules"] = finding.waf_rules
        data["intel"] = finding.intel
    return data


def report_dict(report: ReportModel) -> dict[str, Any]:
    return {
        "id": report.id,
        "workspace_id": report.workspace_id,
        "scan_run_id": report.scan_run_id,
        "name": report.name,
        "format": report.format,
        "template": report.template,
        "language": report.language,
        "filename": report.filename,
        "size": report.size,
        "status": report.status,
        "options": report.options,
        "created_at": iso(report.created_at),
    }


def cve_dict(cve: CveModel) -> dict[str, Any]:
    return {
        "cve_id": cve.cve_id,
        "title": cve.title,
        "description": cve.description,
        "cvss_score": cve.cvss_score,
        "cvss_vector": cve.cvss_vector,
        "severity": cve.severity,
        "published": cve.published,
        "modified": cve.modified,
        "kev": cve.kev,
        "kev_due_date": cve.kev_due_date,
        "epss": cve.epss,
        "epss_percentile": cve.epss_percentile,
        "cwe": cve.cwe,
        "references": cve.references,
        "source": cve.source,
    }


def audit_dict(entry: AuditLogModel) -> dict[str, Any]:
    return {
        "id": entry.id,
        "action": entry.action,
        "actor": entry.actor,
        "target": entry.target,
        "detail": entry.detail,
        "created_at": iso(entry.created_at),
    }
