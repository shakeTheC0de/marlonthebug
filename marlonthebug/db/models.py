"""SQLAlchemy async models for MarlonTheBug."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, func
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from marlonthebug.db.base import Base, str1024, str256, str8192, timestamp_now


def _uuid() -> str:
    return str(uuid.uuid4())


class WorkspaceModel(Base):
    __tablename__ = "workspaces"

    id: Mapped[str] = mapped_column(Text(36), primary_key=True, default=_uuid)
    name: Mapped[str256]
    description: Mapped[str1024] = mapped_column(default="")
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    allow_exploitation: Mapped[bool] = mapped_column(Boolean, default=False)
    require_confirmation: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_domains: Mapped[list] = mapped_column(JSON, default=list)
    allowed_ip_ranges: Mapped[list] = mapped_column(JSON, default=list)
    excluded_targets: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[timestamp_now]
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    targets: Mapped[list["TargetModel"]] = relationship(back_populates="workspace", cascade="all, delete-orphan")


class TargetModel(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(Text(36), primary_key=True, default=_uuid)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    host: Mapped[str256]
    type: Mapped[str256] = mapped_column(default="unknown")
    technologies: Mapped[list] = mapped_column(JSON, default=list)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[timestamp_now]
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    workspace: Mapped["WorkspaceModel"] = relationship(back_populates="targets")
    findings: Mapped[list["FindingModel"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(Text(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    plugin_name: Mapped[str256]
    category: Mapped[str256] = mapped_column(default="web")
    title: Mapped[str1024]
    description: Mapped[str8192] = mapped_column(default="")
    severity: Mapped[str256] = mapped_column(default="info")
    cvss_score: Mapped[float] = mapped_column(default=0.0)
    cvss_vector: Mapped[str1024] = mapped_column(default="")
    endpoint: Mapped[str1024] = mapped_column(default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str8192] = mapped_column(default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    waf_rules: Mapped[list] = mapped_column(JSON, default=list)
    exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[timestamp_now]

    target: Mapped["TargetModel"] = relationship(back_populates="findings")
    exploits: Mapped[list["ExploitModel"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class ExploitModel(Base):
    __tablename__ = "exploits"

    id: Mapped[str] = mapped_column(Text(36), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    module_name: Mapped[str256]
    payload_used: Mapped[str8192] = mapped_column(default="")
    status: Mapped[str256] = mapped_column(default="pending")
    output: Mapped[str8192] = mapped_column(default="")
    error: Mapped[str8192] = mapped_column(default="")
    timestamp: Mapped[timestamp_now]

    finding: Mapped["FindingModel"] = relationship(back_populates="exploits")
    sessions: Mapped[list["SessionModel"]] = relationship(back_populates="exploit", cascade="all, delete-orphan")


class ListenerModel(Base):
    __tablename__ = "listeners"

    id: Mapped[str] = mapped_column(Text(36), primary_key=True, default=_uuid)
    type: Mapped[str256] = mapped_column(default="tcp")
    host: Mapped[str256] = mapped_column(default="0.0.0.0")
    port: Mapped[int] = mapped_column(Integer, default=4444)
    payload_type: Mapped[str256] = mapped_column(default="")
    status: Mapped[str256] = mapped_column(default="stopped")
    workspace_id: Mapped[str | None] = mapped_column(ForeignKey("workspaces.id"), nullable=True)
    created_at: Mapped[timestamp_now]

    sessions: Mapped[list["SessionModel"]] = relationship(back_populates="listener", cascade="all, delete-orphan")


class SessionModel(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(Text(36), primary_key=True, default=_uuid)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("targets.id"), nullable=True)
    exploit_id: Mapped[str | None] = mapped_column(ForeignKey("exploits.id"), nullable=True)
    listener_id: Mapped[str | None] = mapped_column(ForeignKey("listeners.id"), nullable=True)
    type: Mapped[str256] = mapped_column(default="shell")
    user: Mapped[str256] = mapped_column(default="")
    hostname: Mapped[str256] = mapped_column(default="")
    platform: Mapped[str256] = mapped_column(default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    connected_at: Mapped[timestamp_now]
    disconnected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    exploit: Mapped["ExploitModel | None"] = relationship(back_populates="sessions")
    listener: Mapped["ListenerModel | None"] = relationship(back_populates="sessions")
    pivots: Mapped[list["PivotModel"]] = relationship(back_populates="session", cascade="all, delete-orphan")


class PivotModel(Base):
    __tablename__ = "pivots"

    id: Mapped[str] = mapped_column(Text(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    type: Mapped[str256] = mapped_column(default="socks")
    port: Mapped[int] = mapped_column(Integer, default=1080)
    route_info: Mapped[dict] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[timestamp_now]

    session: Mapped["SessionModel"] = relationship(back_populates="pivots")
