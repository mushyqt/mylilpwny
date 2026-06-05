from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session as SASession, sessionmaker

from mylilpwny.persistence.models import (
    AuditEntry,
    Finding,
    Session as PentestSession,
    TargetRecord,
    ToolRun,
)


class SessionManager:
    """CRUD helper for pentest sessions and their related records."""

    def __init__(self, factory: sessionmaker[SASession]) -> None:
        self._factory = factory

    # --- sessions ---

    def create_session(
        self,
        *,
        scope: list[str] | None = None,
        config_snapshot: dict[str, Any] | None = None,
        objective: str | None = None,
    ) -> str:
        """Create a new Session row and return its UUID."""
        db: SASession = self._factory()
        try:
            sess = PentestSession(
                scope=scope or [],
                config_snapshot=config_snapshot or {},
                objective=objective,
                status="running",
            )
            db.add(sess)
            db.commit()
            return str(sess.id)
        finally:
            db.close()

    def get_session(self, session_id: str) -> PentestSession | None:
        db: SASession = self._factory()
        try:
            return db.get(PentestSession, session_id)
        finally:
            db.close()

    def update_status(self, session_id: str, status: str) -> None:
        db: SASession = self._factory()
        try:
            sess = db.get(PentestSession, session_id)
            if sess:
                sess.status = status
                sess.updated_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()

    def list_sessions(self, limit: int = 50) -> list[PentestSession]:
        db: SASession = self._factory()
        try:
            return (
                db.query(PentestSession)
                .order_by(PentestSession.created_at.desc())
                .limit(limit)
                .all()
            )
        finally:
            db.close()

    # --- targets ---

    def upsert_target(
        self,
        session_id: str,
        target_input: str,
        ip: str | None = None,
        hostname: str | None = None,
        state: str = "discovered",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Insert or update a target row; returns its UUID."""
        db: SASession = self._factory()
        try:
            existing = (
                db.query(TargetRecord)
                .filter_by(session_id=session_id, input=target_input)
                .first()
            )
            if existing:
                existing.ip = ip or existing.ip
                existing.hostname = hostname or existing.hostname
                existing.state = state
                if metadata:
                    existing.metadata_json = {**existing.metadata_json, **metadata}
                db.commit()
                return str(existing.id)
            record = TargetRecord(
                session_id=session_id,
                input=target_input,
                ip=ip,
                hostname=hostname,
                state=state,
                metadata_json=metadata or {},
            )
            db.add(record)
            db.commit()
            return str(record.id)
        finally:
            db.close()

    def get_targets(self, session_id: str) -> list[TargetRecord]:
        db: SASession = self._factory()
        try:
            return (
                db.query(TargetRecord)
                .filter_by(session_id=session_id)
                .all()
            )
        finally:
            db.close()

    # --- findings ---

    def add_finding(
        self,
        session_id: str,
        *,
        target_input: str | None = None,
        finding_type: str,
        severity: str = "info",
        title: str,
        description: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> str:
        db: SASession = self._factory()
        try:
            target_id: str | None = None
            if target_input:
                tr = (
                    db.query(TargetRecord)
                    .filter_by(session_id=session_id, input=target_input)
                    .first()
                )
                if tr:
                    target_id = str(tr.id)
            finding = Finding(
                session_id=session_id,
                target_id=target_id,
                finding_type=finding_type,
                severity=severity,
                title=title,
                description=description,
                evidence=evidence or {},
            )
            db.add(finding)
            db.commit()
            return str(finding.id)
        finally:
            db.close()

    # --- tool runs ---

    def log_tool_run(
        self,
        session_id: str,
        *,
        target: str,
        module: str,
        command: str | None = None,
        exit_code: int | None = None,
        duration: float = 0.0,
        status: str = "success",
    ) -> str:
        db: SASession = self._factory()
        try:
            run = ToolRun(
                session_id=session_id,
                target=target,
                module=module,
                command=command,
                exit_code=exit_code,
                duration=duration,
                status=status,
            )
            db.add(run)
            db.commit()
            return str(run.id)
        finally:
            db.close()

    def get_tool_runs(self, session_id: str) -> list[ToolRun]:
        db: SASession = self._factory()
        try:
            return (
                db.query(ToolRun)
                .filter_by(session_id=session_id)
                .order_by(ToolRun.timestamp)
                .all()
            )
        finally:
            db.close()

    # --- audit log ---

    def audit(
        self,
        session_id: str,
        event_type: str,
        *,
        target: str | None = None,
        module: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        db: SASession = self._factory()
        try:
            entry = AuditEntry(
                session_id=session_id,
                event_type=event_type,
                target=target,
                module=module,
                detail=detail or {},
            )
            db.add(entry)
            db.commit()
        finally:
            db.close()

    def get_audit_log(self, session_id: str) -> list[AuditEntry]:
        db: SASession = self._factory()
        try:
            return (
                db.query(AuditEntry)
                .filter_by(session_id=session_id)
                .order_by(AuditEntry.timestamp)
                .all()
            )
        finally:
            db.close()
