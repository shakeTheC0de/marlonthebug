"""SQLAlchemy models — the persistent source of truth for the platform."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class WorkspaceModel(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    client_name: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    allow_exploitation: Mapped[bool] = mapped_column(Boolean, default=False)
    require_confirmation: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    targets: Mapped[list[TargetModel]] = relationship(
        back_populates="workspace", cascade="all, delete-orphan", lazy="selectin"
    )
    scans: Mapped[list[ScanRunModel]] = relationship(back_populates="workspace", cascade="all, delete-orphan")
    findings: Mapped[list[FindingModel]] = relationship(back_populates="workspace", cascade="all, delete-orphan")
    reports: Mapped[list[ReportModel]] = relationship(back_populates="workspace", cascade="all, delete-orphan")


class TargetModel(Base):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("workspace_id", "host", name="uq_target_workspace_host"),
        Index("ix_targets_workspace", "workspace_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    host: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(40), default="web")
    technologies: Mapped[list] = mapped_column(JSON, default=list)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    workspace: Mapped[WorkspaceModel] = relationship(back_populates="targets")
    findings: Mapped[list[FindingModel]] = relationship(back_populates="target")
    intel: Mapped[list[AssetIntelModel]] = relationship(back_populates="target", cascade="all, delete-orphan")


class ScanRunModel(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (Index("ix_scans_workspace_status", "workspace_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    profile: Mapped[str] = mapped_column(String(40), default="standard")
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    targets: Mapped[list] = mapped_column(JSON, default=list)
    categories: Mapped[list] = mapped_column(JSON, default=list)
    modules: Mapped[list] = mapped_column(JSON, default=list)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    logs: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(120), default="panel")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    workspace: Mapped[WorkspaceModel] = relationship(back_populates="scans")
    findings: Mapped[list[FindingModel]] = relationship(back_populates="scan_run")
    reports: Mapped[list[ReportModel]] = relationship(back_populates="scan_run")


class FindingModel(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("workspace_id", "fingerprint", name="uq_finding_workspace_fingerprint"),
        Index("ix_findings_workspace_severity", "workspace_id", "severity"),
        Index("ix_findings_created", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    scan_run_id: Mapped[str | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    plugin_name: Mapped[str] = mapped_column(String(120), default="")
    category: Mapped[str] = mapped_column(String(60), default="web")
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    cvss_vector: Mapped[str] = mapped_column(String(300), default="")
    cwe: Mapped[str] = mapped_column(String(40), default="")
    owasp: Mapped[str] = mapped_column(String(120), default="")
    endpoint: Mapped[str] = mapped_column(String(2048), default="")
    target_host: Mapped[str] = mapped_column(String(255), default="", index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    waf_rules: Mapped[list] = mapped_column(JSON, default=list)
    intel: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    epss: Mapped[float] = mapped_column(Float, default=0.0)
    occurrences: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    workspace: Mapped[WorkspaceModel] = relationship(back_populates="findings")
    scan_run: Mapped[ScanRunModel | None] = relationship(back_populates="findings")
    target: Mapped[TargetModel | None] = relationship(back_populates="findings")
    exploit_runs: Mapped[list[ExploitRunModel]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )


class ReportModel(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    scan_run_id: Mapped[str | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    format: Mapped[str] = mapped_column(String(20), default="pdf")
    template: Mapped[str] = mapped_column(String(40), default="full")
    language: Mapped[str] = mapped_column(String(10), default="es")
    filename: Mapped[str] = mapped_column(String(255), default="")
    path: Mapped[str] = mapped_column(String(2048), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="ready")
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    workspace: Mapped[WorkspaceModel] = relationship(back_populates="reports")
    scan_run: Mapped[ScanRunModel | None] = relationship(back_populates="reports")


class ExploitRunModel(Base):
    __tablename__ = "exploit_runs"
    __table_args__ = (Index("ix_exploits_workspace_created", "workspace_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    module_name: Mapped[str] = mapped_column(String(120))
    module_category: Mapped[str] = mapped_column(String(60), default="webapp")
    risk: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="running", index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    output: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    operator: Mapped[str] = mapped_column(String(120), default="panel")
    cleanup_status: Mapped[str] = mapped_column(String(30), default="not_required")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    finding: Mapped[FindingModel] = relationship(back_populates="exploit_runs")
    workspace: Mapped[WorkspaceModel] = relationship()
    target: Mapped[TargetModel | None] = relationship()


class AuditLogModel(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    action: Mapped[str] = mapped_column(String(120), index=True)
    actor: Mapped[str] = mapped_column(String(120), default="local")
    target: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IntelFeedModel(Base):
    __tablename__ = "intel_feeds"

    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    source: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(30), default="never")
    count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CveModel(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(500), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    cvss_vector: Mapped[str] = mapped_column(String(300), default="")
    severity: Mapped[str] = mapped_column(String(20), default="unknown", index=True)
    published: Mapped[str] = mapped_column(String(40), default="")
    modified: Mapped[str] = mapped_column(String(40), default="")
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_due_date: Mapped[str] = mapped_column(String(40), default="")
    epss: Mapped[float] = mapped_column(Float, default=0.0)
    epss_percentile: Mapped[float] = mapped_column(Float, default=0.0)
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)
    affected: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(40), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AssetIntelModel(Base):
    __tablename__ = "asset_intel"
    __table_args__ = (UniqueConstraint("target_id", "product", "version", "cve_id", name="uq_asset_intel"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    product: Mapped[str] = mapped_column(String(120))
    version: Mapped[str] = mapped_column(String(80), default="")
    cve_id: Mapped[str] = mapped_column(String(32), default="")
    match_type: Mapped[str] = mapped_column(String(40), default="version")
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    source: Mapped[str] = mapped_column(String(40), default="osv")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    target: Mapped[TargetModel] = relationship(back_populates="intel")
