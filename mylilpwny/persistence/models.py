from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

# Canonical severity levels — order matches ascending criticality
FindingSeverity = Literal["info", "low", "medium", "high", "critical"]

# Canonical finding types produced by pipeline stages
FindingType = Literal[
    "recon",
    "open_port",
    "service",
    "vulnerability",
    "credential",
    "web_finding",
]

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Session(Base):
    """One pentest run == one Session."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    scope: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="running")
    objective: Mapped[str | None] = mapped_column(String(64), nullable=True)

    targets: Mapped[list[TargetRecord]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    tool_runs: Mapped[list[ToolRun]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    audit_entries: Mapped[list[AuditEntry]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class TargetRecord(Base):
    """Persisted state of a single target within a session."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    input: Mapped[str] = mapped_column(String(256))
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="discovered")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    session: Mapped[Session] = relationship(back_populates="targets")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="target_record", cascade="all, delete-orphan"
    )


class Finding(Base):
    """A single finding (port, service, vulnerability, web finding, etc.)."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finding_type: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    session: Mapped[Session] = relationship(back_populates="findings")
    target_record: Mapped[TargetRecord | None] = relationship(back_populates="findings")


class ToolRun(Base):
    """Record of a single tool execution."""

    __tablename__ = "tool_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    target: Mapped[str] = mapped_column(String(256))
    module: Mapped[str] = mapped_column(String(64))
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration: Mapped[float] = mapped_column(default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="success")

    session: Mapped[Session] = relationship(back_populates="tool_runs")


class AuditEntry(Base):
    """Immutable audit log — never deleted, one row per notable event."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    event_type: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    session: Mapped[Session] = relationship(back_populates="audit_entries")
