"""Repository layer — all database access goes through this module."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.orm import selectinload

from marlonthebug.db.database import Database
from marlonthebug.db.models import (
    AssetIntelModel,
    AuditLogModel,
    CveModel,
    ExploitRunModel,
    FindingModel,
    IntelFeedModel,
    ReportModel,
    ScanRunModel,
    TargetModel,
    WorkspaceModel,
    utcnow,
)

logger = logging.getLogger("marlonthebug.repository")

SEVERITY_ORDER = case(
    (FindingModel.severity == "critical", 0),
    (FindingModel.severity == "high", 1),
    (FindingModel.severity == "medium", 2),
    (FindingModel.severity == "low", 3),
    (FindingModel.severity == "info", 4),
    else_=5,
)


def finding_fingerprint(
    plugin_name: str,
    title: str,
    endpoint: str = "",
    target_host: str = "",
    parameter: str = "",
) -> str:
    normalized = "|".join(part.strip().lower() for part in (plugin_name, title, endpoint, target_host, parameter))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ── Workspaces ──────────────────────────────────────────

    async def create_workspace(
        self,
        name: str,
        client_name: str = "",
        description: str = "",
        scope: dict | None = None,
        allow_exploitation: bool = False,
        require_confirmation: bool = True,
    ) -> WorkspaceModel:
        async with self.db.session() as session:
            workspace = WorkspaceModel(
                name=name.strip(),
                client_name=client_name.strip(),
                description=description.strip(),
                scope=scope
                or {
                    "allowed_domains": [],
                    "allowed_ip_ranges": [],
                    "excluded": [],
                },
                allow_exploitation=allow_exploitation,
                require_confirmation=require_confirmation,
            )
            session.add(workspace)
            await session.flush()
            return workspace

    async def get_workspace(self, workspace_id: str) -> WorkspaceModel | None:
        async with self.db.session() as session:
            result = await session.execute(
                select(WorkspaceModel)
                .options(selectinload(WorkspaceModel.targets))
                .where(WorkspaceModel.id == workspace_id)
            )
            return result.scalar_one_or_none()

    async def get_workspace_by_name(self, name: str) -> WorkspaceModel | None:
        async with self.db.session() as session:
            result = await session.execute(select(WorkspaceModel).where(WorkspaceModel.name == name))
            return result.scalar_one_or_none()

    async def list_workspaces(self) -> list[WorkspaceModel]:
        async with self.db.session() as session:
            result = await session.execute(
                select(WorkspaceModel)
                .options(selectinload(WorkspaceModel.targets))
                .order_by(WorkspaceModel.updated_at.desc())
            )
            return list(result.scalars().all())

    async def update_workspace(self, workspace_id: str, **fields: Any) -> WorkspaceModel | None:
        async with self.db.session() as session:
            workspace = await session.get(WorkspaceModel, workspace_id)
            if not workspace:
                return None
            for key, value in fields.items():
                if hasattr(workspace, key):
                    setattr(workspace, key, value)
            workspace.updated_at = utcnow()
            return workspace

    async def delete_workspace(self, workspace_id: str) -> bool:
        async with self.db.session() as session:
            workspace = await session.get(WorkspaceModel, workspace_id)
            if not workspace:
                return False
            await session.delete(workspace)
            return True

    # ── Targets ─────────────────────────────────────────────

    async def add_target(
        self,
        workspace_id: str,
        host: str,
        kind: str = "web",
        technologies: list[str] | None = None,
        ports: list[int] | None = None,
        metadata: dict | None = None,
    ) -> TargetModel | None:
        host = _normalize_host(host)
        async with self.db.session() as session:
            workspace = await session.get(WorkspaceModel, workspace_id)
            if not workspace:
                return None
            result = await session.execute(
                select(TargetModel).where(
                    TargetModel.workspace_id == workspace_id,
                    TargetModel.host == host,
                )
            )
            target = result.scalar_one_or_none()
            if target:
                if kind:
                    target.kind = kind
                if technologies:
                    target.technologies = sorted(set((target.technologies or []) + technologies))
                if ports:
                    target.ports = sorted(set((target.ports or []) + ports))
                if metadata:
                    target.metadata_ = {**(target.metadata_ or {}), **metadata}
                target.last_seen = utcnow()
            else:
                target = TargetModel(
                    workspace_id=workspace_id,
                    host=host,
                    kind=kind,
                    technologies=technologies or [],
                    ports=ports or [],
                    metadata_=metadata or {},
                )
                session.add(target)
            scope = dict(workspace.scope or {})
            domains = list(scope.get("allowed_domains", []))
            ranges = list(scope.get("allowed_ip_ranges", []))
            scope_host = _scope_host(host)
            if _looks_like_ip(scope_host):
                if scope_host not in ranges:
                    ranges.append(scope_host)
            elif scope_host not in domains:
                domains.append(scope_host)
            scope["allowed_domains"] = domains
            scope["allowed_ip_ranges"] = ranges
            workspace.scope = scope
            workspace.updated_at = utcnow()
            await session.flush()
            return target

    async def get_target(self, target_id: str) -> TargetModel | None:
        async with self.db.session() as session:
            result = await session.execute(
                select(TargetModel).options(selectinload(TargetModel.intel)).where(TargetModel.id == target_id)
            )
            return result.scalar_one_or_none()

    async def get_target_by_host(self, workspace_id: str, host: str) -> TargetModel | None:
        async with self.db.session() as session:
            result = await session.execute(
                select(TargetModel).where(
                    TargetModel.workspace_id == workspace_id,
                    TargetModel.host == host.lower().strip(),
                )
            )
            return result.scalar_one_or_none()

    async def list_targets(self, workspace_id: str) -> list[TargetModel]:
        async with self.db.session() as session:
            result = await session.execute(
                select(TargetModel).where(TargetModel.workspace_id == workspace_id).order_by(TargetModel.host)
            )
            return list(result.scalars().all())

    async def list_assets(self, workspace_id: str) -> list[tuple[TargetModel, int]]:
        async with self.db.session() as session:
            result = await session.execute(
                select(TargetModel, func.count(FindingModel.id))
                .outerjoin(FindingModel, FindingModel.target_id == TargetModel.id)
                .where(TargetModel.workspace_id == workspace_id)
                .group_by(TargetModel.id)
                .order_by(TargetModel.host)
            )
            return [(row[0], int(row[1])) for row in result.all()]

    async def delete_target(self, target_id: str) -> bool:
        async with self.db.session() as session:
            target = await session.get(TargetModel, target_id)
            if not target:
                return False
            await session.delete(target)
            return True

    # ── Scans ───────────────────────────────────────────────

    async def create_scan(
        self,
        workspace_id: str,
        targets: list[str],
        categories: list[str],
        modules: list[str] | None = None,
        profile: str = "standard",
        options: dict | None = None,
        created_by: str = "panel",
    ) -> ScanRunModel:
        async with self.db.session() as session:
            scan = ScanRunModel(
                workspace_id=workspace_id,
                targets=targets,
                categories=categories,
                modules=modules or [],
                profile=profile,
                options=options or {},
                created_by=created_by,
                status="pending",
            )
            session.add(scan)
            await session.flush()
            return scan

    async def update_scan(self, scan_id: str, **fields: Any) -> ScanRunModel | None:
        async with self.db.session() as session:
            scan = await session.get(ScanRunModel, scan_id)
            if not scan:
                return None
            for key, value in fields.items():
                if hasattr(scan, key):
                    setattr(scan, key, value)
            return scan

    async def get_scan(self, scan_id: str, with_workspace: bool = False) -> ScanRunModel | None:
        async with self.db.session() as session:
            statement = select(ScanRunModel).where(ScanRunModel.id == scan_id)
            if with_workspace:
                statement = statement.options(selectinload(ScanRunModel.workspace).selectinload(WorkspaceModel.targets))
            result = await session.execute(statement)
            return result.scalar_one_or_none()

    async def list_scans(
        self,
        workspace_id: str | None = None,
        limit: int = 50,
    ) -> list[ScanRunModel]:
        async with self.db.session() as session:
            statement = (
                select(ScanRunModel)
                .options(selectinload(ScanRunModel.workspace))
                .order_by(ScanRunModel.created_at.desc())
                .limit(limit)
            )
            if workspace_id:
                statement = statement.where(ScanRunModel.workspace_id == workspace_id)
            result = await session.execute(statement)
            return list(result.scalars().all())

    async def mark_interrupted_scans(self) -> int:
        async with self.db.session() as session:
            result = await session.execute(select(ScanRunModel).where(ScanRunModel.status.in_(["pending", "running"])))
            scans = list(result.scalars().all())
            for scan in scans:
                scan.status = "interrupted"
                scan.error = "La aplicación se reinició antes de terminar el análisis."
                scan.finished_at = utcnow()
            return len(scans)

    # ── Findings ────────────────────────────────────────────

    async def upsert_finding(self, data: dict[str, Any]) -> tuple[FindingModel, bool]:
        workspace_id = data["workspace_id"]
        fingerprint = data.get("fingerprint") or finding_fingerprint(
            data.get("plugin_name", ""),
            data.get("title", ""),
            data.get("endpoint", ""),
            data.get("target_host", ""),
            str((data.get("evidence") or {}).get("parameter", "")),
        )
        async with self.db.session() as session:
            result = await session.execute(
                select(FindingModel).where(
                    FindingModel.workspace_id == workspace_id,
                    FindingModel.fingerprint == fingerprint,
                )
            )
            existing = result.scalar_one_or_none()
            if existing:
                existing.last_seen = utcnow()
                existing.scan_run_id = data.get("scan_run_id") or existing.scan_run_id
                if data.get("target_id"):
                    existing.target_id = data["target_id"]
                if data.get("severity") and _severity_rank(data["severity"]) < _severity_rank(existing.severity):
                    existing.severity = data["severity"]
                if data.get("cvss_score", 0) > existing.cvss_score:
                    existing.cvss_score = data["cvss_score"]
                if data.get("cvss_vector"):
                    existing.cvss_vector = data["cvss_vector"]
                if data.get("confidence"):
                    existing.confidence = data["confidence"]
                if data.get("endpoint"):
                    existing.endpoint = data["endpoint"]
                if data.get("evidence"):
                    existing.evidence = {**(existing.evidence or {}), **data["evidence"]}
                if data.get("intel"):
                    existing.intel = {**(existing.intel or {}), **data["intel"]}
                if data.get("kev"):
                    existing.kev = True
                if data.get("epss", 0) > existing.epss:
                    existing.epss = data["epss"]
                if data.get("verified"):
                    existing.verified = True
                occurrences = list(existing.occurrences or [])
                if data.get("scan_run_id") and data["scan_run_id"] not in occurrences:
                    occurrences.append(data["scan_run_id"])
                existing.occurrences = occurrences[-50:]
                existing.updated_at = utcnow()
                return existing, False

            allowed = {
                "workspace_id",
                "scan_run_id",
                "target_id",
                "plugin_name",
                "category",
                "title",
                "description",
                "severity",
                "confidence",
                "status",
                "cvss_score",
                "cvss_vector",
                "cwe",
                "owasp",
                "endpoint",
                "target_host",
                "evidence",
                "remediation",
                "references",
                "waf_rules",
                "intel",
                "notes",
                "verified",
                "kev",
                "epss",
            }
            values = {key: value for key, value in data.items() if key in allowed}
            finding = FindingModel(**values, fingerprint=fingerprint)
            if data.get("scan_run_id"):
                finding.occurrences = [data["scan_run_id"]]
            session.add(finding)
            await session.flush()
            return finding, True

    async def bulk_upsert_findings(self, findings: list[dict[str, Any]]) -> tuple[int, int]:
        created = 0
        updated = 0
        for data in findings:
            _, is_new = await self.upsert_finding(data)
            if is_new:
                created += 1
            else:
                updated += 1
        return created, updated

    async def get_finding(self, finding_id: str) -> FindingModel | None:
        async with self.db.session() as session:
            result = await session.execute(
                select(FindingModel)
                .options(
                    selectinload(FindingModel.target),
                    selectinload(FindingModel.scan_run),
                    selectinload(FindingModel.workspace),
                )
                .where(FindingModel.id == finding_id)
            )
            return result.scalar_one_or_none()

    async def list_findings(
        self,
        workspace_id: str | None = None,
        severities: list[str] | None = None,
        statuses: list[str] | None = None,
        categories: list[str] | None = None,
        search: str | None = None,
        kev_only: bool = False,
        verified_only: bool = False,
        page: int = 1,
        page_size: int = 50,
        sort: str = "severity",
    ) -> tuple[list[FindingModel], int]:
        conditions = []
        if workspace_id:
            conditions.append(FindingModel.workspace_id == workspace_id)
        if severities:
            conditions.append(FindingModel.severity.in_(severities))
        if statuses:
            conditions.append(FindingModel.status.in_(statuses))
        if categories:
            conditions.append(FindingModel.category.in_(categories))
        if kev_only:
            conditions.append(FindingModel.kev.is_(True))
        if verified_only:
            conditions.append(FindingModel.verified.is_(True))
        if search:
            needle = f"%{search.strip()}%"
            conditions.append(
                or_(
                    FindingModel.title.ilike(needle),
                    FindingModel.description.ilike(needle),
                    FindingModel.endpoint.ilike(needle),
                    FindingModel.target_host.ilike(needle),
                    FindingModel.plugin_name.ilike(needle),
                )
            )

        page = max(1, page)
        page_size = max(1, min(page_size, 200))

        async with self.db.session() as session:
            count_result = await session.execute(select(func.count()).select_from(FindingModel).where(*conditions))
            total = int(count_result.scalar_one())

            statement = select(FindingModel).options(selectinload(FindingModel.target)).where(*conditions)
            if sort == "cvss":
                statement = statement.order_by(FindingModel.cvss_score.desc())
            elif sort == "recent":
                statement = statement.order_by(FindingModel.last_seen.desc())
            elif sort == "kev":
                statement = statement.order_by(FindingModel.kev.desc(), SEVERITY_ORDER)
            else:
                statement = statement.order_by(SEVERITY_ORDER, FindingModel.cvss_score.desc())
            statement = statement.offset((page - 1) * page_size).limit(page_size)
            result = await session.execute(statement)
            return list(result.scalars().all()), total

    async def list_findings_for_target(
        self,
        target_id: str,
        limit: int = 200,
    ) -> list[FindingModel]:
        async with self.db.session() as session:
            result = await session.execute(
                select(FindingModel)
                .where(FindingModel.target_id == target_id)
                .order_by(SEVERITY_ORDER, FindingModel.cvss_score.desc())
                .limit(limit)
            )
            return list(result.scalars().all())

    async def list_all_findings(
        self,
        workspace_id: str | None = None,
        limit: int = 5000,
    ) -> list[FindingModel]:
        async with self.db.session() as session:
            statement = (
                select(FindingModel)
                .options(
                    selectinload(FindingModel.target),
                    selectinload(FindingModel.workspace),
                )
                .order_by(SEVERITY_ORDER, FindingModel.cvss_score.desc())
                .limit(max(1, min(limit, 20000)))
            )
            if workspace_id:
                statement = statement.where(FindingModel.workspace_id == workspace_id)
            result = await session.execute(statement)
            return list(result.scalars().all())

    async def update_finding(self, finding_id: str, **fields: Any) -> FindingModel | None:
        allowed = {"status", "notes", "severity", "confidence", "verified", "kev", "epss", "intel"}
        async with self.db.session() as session:
            finding = await session.get(FindingModel, finding_id)
            if not finding:
                return None
            for key, value in fields.items():
                if key in allowed:
                    setattr(finding, key, value)
            finding.updated_at = utcnow()
            return finding

    async def delete_finding(self, finding_id: str) -> bool:
        async with self.db.session() as session:
            finding = await session.get(FindingModel, finding_id)
            if not finding:
                return False
            await session.delete(finding)
            return True

    # ── Exploitation ────────────────────────────────────────

    async def create_exploit_run(
        self,
        workspace_id: str,
        finding_id: str,
        module_name: str,
        module_category: str = "webapp",
        risk: str = "medium",
        payload: dict | None = None,
        operator: str = "panel",
        target_id: str | None = None,
    ) -> ExploitRunModel:
        async with self.db.session() as session:
            run = ExploitRunModel(
                workspace_id=workspace_id,
                finding_id=finding_id,
                target_id=target_id,
                module_name=module_name,
                module_category=module_category,
                risk=risk,
                payload=payload or {},
                operator=operator,
                status="running",
            )
            session.add(run)
            await session.flush()
            return run

    async def update_exploit_run(self, run_id: str, **fields: Any) -> ExploitRunModel | None:
        async with self.db.session() as session:
            run = await session.get(ExploitRunModel, run_id)
            if not run:
                return None
            for key, value in fields.items():
                if hasattr(run, key):
                    setattr(run, key, value)
            return run

    async def get_exploit_run(self, run_id: str) -> ExploitRunModel | None:
        async with self.db.session() as session:
            result = await session.execute(
                select(ExploitRunModel)
                .options(
                    selectinload(ExploitRunModel.finding),
                    selectinload(ExploitRunModel.workspace),
                    selectinload(ExploitRunModel.target),
                )
                .where(ExploitRunModel.id == run_id)
            )
            return result.scalar_one_or_none()

    async def list_exploit_runs(
        self,
        workspace_id: str | None = None,
        finding_id: str | None = None,
        limit: int = 100,
    ) -> list[ExploitRunModel]:
        async with self.db.session() as session:
            statement = (
                select(ExploitRunModel)
                .options(
                    selectinload(ExploitRunModel.finding),
                    selectinload(ExploitRunModel.workspace),
                )
                .order_by(ExploitRunModel.created_at.desc())
                .limit(limit)
            )
            if workspace_id:
                statement = statement.where(ExploitRunModel.workspace_id == workspace_id)
            if finding_id:
                statement = statement.where(ExploitRunModel.finding_id == finding_id)
            result = await session.execute(statement)
            return list(result.scalars().all())

    # ── Dashboard / statistics ──────────────────────────────

    async def dashboard_stats(self, workspace_id: str | None = None) -> dict[str, Any]:
        where = (FindingModel.workspace_id == workspace_id,) if workspace_id else ()
        async with self.db.session() as session:
            severity_result = await session.execute(
                select(FindingModel.severity, func.count()).where(*where).group_by(FindingModel.severity)
            )
            severity = {row[0]: int(row[1]) for row in severity_result.all()}

            status_result = await session.execute(
                select(FindingModel.status, func.count()).where(*where).group_by(FindingModel.status)
            )
            statuses = {row[0]: int(row[1]) for row in status_result.all()}

            category_result = await session.execute(
                select(FindingModel.category, func.count())
                .where(*where)
                .group_by(FindingModel.category)
                .order_by(func.count().desc())
            )
            categories = {row[0]: int(row[1]) for row in category_result.all()}

            plugin_result = await session.execute(
                select(FindingModel.plugin_name, func.count())
                .where(*where)
                .group_by(FindingModel.plugin_name)
                .order_by(func.count().desc())
                .limit(8)
            )
            plugins = [(row[0], int(row[1])) for row in plugin_result.all()]

            total = sum(severity.values())
            kev_result = await session.execute(
                select(func.count()).select_from(FindingModel).where(*where, FindingModel.kev.is_(True))
            )
            kev_count = int(kev_result.scalar_one())

            if workspace_id:
                assets_result = await session.execute(
                    select(func.count()).select_from(TargetModel).where(TargetModel.workspace_id == workspace_id)
                )
                scans_result = await session.execute(
                    select(func.count()).select_from(ScanRunModel).where(ScanRunModel.workspace_id == workspace_id)
                )
                reports_result = await session.execute(
                    select(func.count()).select_from(ReportModel).where(ReportModel.workspace_id == workspace_id)
                )
            else:
                assets_result = await session.execute(select(func.count()).select_from(TargetModel))
                scans_result = await session.execute(select(func.count()).select_from(ScanRunModel))
                reports_result = await session.execute(select(func.count()).select_from(ReportModel))

            recent_result = await session.execute(
                select(FindingModel).where(*where).order_by(FindingModel.last_seen.desc()).limit(6)
            )
            recent_findings = list(recent_result.scalars().all())

            dynamic_where = (*where, FindingModel.created_at >= datetime.now(UTC) - timedelta(days=14))
            trend_result = await session.execute(
                select(func.date(FindingModel.created_at), func.count())
                .where(*dynamic_where)
                .group_by(func.date(FindingModel.created_at))
                .order_by(func.date(FindingModel.created_at))
            )
            trend = [(str(row[0]), int(row[1])) for row in trend_result.all()]

            return {
                "severity": severity,
                "statuses": statuses,
                "categories": categories,
                "plugins": plugins,
                "total": total,
                "kev": kev_count,
                "assets": int(assets_result.scalar_one()),
                "scans": int(scans_result.scalar_one()),
                "reports": int(reports_result.scalar_one()),
                "recent_findings": recent_findings,
                "trend": trend,
            }

    # ── Reports ─────────────────────────────────────────────

    async def create_report(
        self,
        workspace_id: str,
        name: str,
        format: str,
        template: str,
        language: str,
        filename: str,
        path: str,
        size: int,
        scan_run_id: str | None = None,
        options: dict | None = None,
        status: str = "ready",
    ) -> ReportModel:
        async with self.db.session() as session:
            report = ReportModel(
                workspace_id=workspace_id,
                scan_run_id=scan_run_id,
                name=name,
                format=format,
                template=template,
                language=language,
                filename=filename,
                path=path,
                size=size,
                options=options or {},
                status=status,
            )
            session.add(report)
            await session.flush()
            return report

    async def list_reports(
        self,
        workspace_id: str | None = None,
        limit: int = 100,
    ) -> list[ReportModel]:
        async with self.db.session() as session:
            statement = (
                select(ReportModel)
                .options(selectinload(ReportModel.workspace))
                .order_by(ReportModel.created_at.desc())
                .limit(limit)
            )
            if workspace_id:
                statement = statement.where(ReportModel.workspace_id == workspace_id)
            result = await session.execute(statement)
            return list(result.scalars().all())

    async def get_report(self, report_id: str) -> ReportModel | None:
        async with self.db.session() as session:
            result = await session.execute(
                select(ReportModel)
                .options(selectinload(ReportModel.workspace), selectinload(ReportModel.scan_run))
                .where(ReportModel.id == report_id)
            )
            return result.scalar_one_or_none()

    async def delete_report(self, report_id: str) -> bool:
        async with self.db.session() as session:
            report = await session.get(ReportModel, report_id)
            if not report:
                return False
            await session.delete(report)
            return True

    # ── Audit log ───────────────────────────────────────────

    async def log_action(
        self,
        action: str,
        actor: str = "local",
        target: str = "",
        detail: dict | None = None,
    ) -> None:
        async with self.db.session() as session:
            session.add(
                AuditLogModel(
                    action=action,
                    actor=actor,
                    target=target,
                    detail=detail or {},
                )
            )

    async def list_audit(self, limit: int = 100) -> list[AuditLogModel]:
        async with self.db.session() as session:
            result = await session.execute(select(AuditLogModel).order_by(AuditLogModel.created_at.desc()).limit(limit))
            return list(result.scalars().all())

    # ── Intel ───────────────────────────────────────────────

    async def upsert_feed(
        self,
        name: str,
        source: str,
        status: str,
        count: int,
        error: str = "",
        metadata: dict | None = None,
    ) -> IntelFeedModel:
        async with self.db.session() as session:
            feed = await session.get(IntelFeedModel, name)
            if not feed:
                feed = IntelFeedModel(name=name)
                session.add(feed)
            feed.source = source
            feed.status = status
            feed.count = count
            feed.error = error
            feed.metadata_ = metadata or {}
            feed.last_sync = utcnow()
            await session.flush()
            return feed

    async def list_feeds(self) -> list[IntelFeedModel]:
        async with self.db.session() as session:
            result = await session.execute(select(IntelFeedModel))
            return list(result.scalars().all())

    async def get_feed(self, name: str) -> IntelFeedModel | None:
        async with self.db.session() as session:
            return await session.get(IntelFeedModel, name)

    async def upsert_cve(self, data: dict[str, Any]) -> CveModel:
        async with self.db.session() as session:
            cve = await session.get(CveModel, data["cve_id"])
            if not cve:
                cve = CveModel(cve_id=data["cve_id"])
                session.add(cve)
            for key, value in data.items():
                if hasattr(cve, key) and key != "cve_id":
                    setattr(cve, key, value)
            cve.updated_at = utcnow()
            await session.flush()
            return cve

    async def bulk_upsert_cves(self, rows: list[dict[str, Any]]) -> int:
        async with self.db.session() as session:
            existing_result = await session.execute(select(CveModel))
            existing = {cve.cve_id: cve for cve in existing_result.scalars().all()}
            for data in rows:
                cve = existing.get(data["cve_id"])
                if not cve:
                    cve = CveModel(cve_id=data["cve_id"])
                    session.add(cve)
                for key, value in data.items():
                    if hasattr(cve, key) and key != "cve_id":
                        setattr(cve, key, value)
                cve.updated_at = utcnow()
            return len(rows)

    async def get_cve(self, cve_id: str) -> CveModel | None:
        async with self.db.session() as session:
            return await session.get(CveModel, cve_id)

    async def search_cves(self, query: str, limit: int = 50) -> list[CveModel]:
        needle = f"%{query.strip()}%"
        async with self.db.session() as session:
            result = await session.execute(
                select(CveModel)
                .where(
                    or_(
                        CveModel.cve_id.ilike(needle),
                        CveModel.title.ilike(needle),
                        CveModel.description.ilike(needle),
                    )
                )
                .order_by(CveModel.kev.desc(), CveModel.epss.desc(), CveModel.cvss_score.desc())
                .limit(limit)
            )
            return list(result.scalars().all())

    async def list_kev(self, limit: int = 100) -> list[CveModel]:
        async with self.db.session() as session:
            result = await session.execute(
                select(CveModel)
                .where(CveModel.kev.is_(True))
                .order_by(CveModel.epss.desc(), CveModel.cvss_score.desc())
                .limit(limit)
            )
            return list(result.scalars().all())

    async def intel_stats(self) -> dict[str, Any]:
        async with self.db.session() as session:
            total = await session.execute(select(func.count()).select_from(CveModel))
            kev = await session.execute(select(func.count()).select_from(CveModel).where(CveModel.kev.is_(True)))
            epss = await session.execute(select(func.count()).select_from(CveModel).where(CveModel.epss > 0))
            reports = await session.execute(select(func.count()).select_from(CveModel).where(CveModel.source == "nvd"))
            return {
                "total": int(total.scalar_one()),
                "kev": int(kev.scalar_one()),
                "epss": int(epss.scalar_one()),
                "nvd": int(reports.scalar_one()),
            }

    async def replace_asset_intel(self, target_id: str, rows: list[dict[str, Any]]) -> int:
        async with self.db.session() as session:
            await session.execute(delete(AssetIntelModel).where(AssetIntelModel.target_id == target_id))
            for row in rows:
                session.add(AssetIntelModel(target_id=target_id, **row))
            return len(rows)

    async def list_asset_intel(self, target_id: str) -> list[AssetIntelModel]:
        async with self.db.session() as session:
            result = await session.execute(
                select(AssetIntelModel)
                .where(AssetIntelModel.target_id == target_id)
                .order_by(AssetIntelModel.product, AssetIntelModel.cve_id)
            )
            return list(result.scalars().all())


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value.split("/")[0])
        return True
    except ValueError:
        return False


def _scope_host(value: str) -> str:
    from urllib.parse import urlparse

    candidate = value.strip().lower()
    if "://" in candidate:
        return urlparse(candidate).hostname or candidate
    return urlparse(f"//{candidate}").hostname or candidate


def _normalize_host(value: str) -> str:
    from urllib.parse import urlparse

    candidate = value.strip().lower()
    if "://" in candidate:
        return (urlparse(candidate).netloc or candidate).lower()
    return candidate.split("/")[0]
