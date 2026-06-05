from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session as SASession, sessionmaker

from mylilpwny.persistence.models import (
    AuditEntry,
    Finding,
    Session as PentestSession,
    TargetRecord,
    ToolRun,
)

# --------------------------------------------------------------------------- #
#  Stage → Finding conversion                                                  #
# --------------------------------------------------------------------------- #

def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def stage_to_findings(
    stage: str, parsed_findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Convert ModuleResult.parsed_findings into a list of Finding kwargs dicts.

    Each dict has: finding_type, severity, title, description, evidence.
    """
    out: list[dict[str, Any]] = []

    if stage == "recon":
        if not parsed_findings:
            return out
        r = parsed_findings[0]
        hosts = r.get("hostnames", []) + r.get("ips", [])
        out.append({
            "finding_type": "recon",
            "severity": "info",
            "title": f"Recon: {len(hosts)} host(s) discovered",
            "description": "",
            "evidence": r,
        })
        # Individual subdomain findings
        for h in r.get("hostnames", []):
            out.append({
                "finding_type": "recon",
                "severity": "info",
                "title": f"Subdomain: {h}",
                "description": "",
                "evidence": {"hostname": h},
            })

    elif stage == "portscan":
        for p in parsed_findings:
            port = p.get("port", "?")
            proto = p.get("protocol", "tcp")
            out.append({
                "finding_type": "open_port",
                "severity": "medium",
                "title": f"Port {port}/{proto} open",
                "description": "",
                "evidence": p,
            })

    elif stage == "servicenum":
        for s in parsed_findings:
            name = s.get("name", "unknown")
            port = s.get("port", "?")
            version = s.get("version") or ""
            title = f"Service {name} on port {port}"
            if version:
                title += f" ({version})"
            out.append({
                "finding_type": "service",
                "severity": "info",
                "title": title,
                "description": "",
                "evidence": s,
            })

    elif stage == "vulnanalysis":
        for v in parsed_findings:
            cvss = v.get("cvss")
            severity = v.get("severity") or _cvss_to_severity(cvss)
            cve = v.get("cve_id") or v.get("title", "unknown")
            desc = v.get("description", "")
            out.append({
                "finding_type": "vulnerability",
                "severity": severity.lower() if isinstance(severity, str) else "info",
                "title": cve,
                "description": desc,
                "evidence": v,
            })

    return out


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

    def list_sessions_with_counts(self, limit: int = 50) -> list[tuple[PentestSession, int]]:
        """Return (session, target_count) pairs — no lazy loading needed."""
        db: SASession = self._factory()
        try:
            rows = (
                db.query(PentestSession, func.count(TargetRecord.id).label("target_count"))
                .outerjoin(TargetRecord, TargetRecord.session_id == PentestSession.id)
                .group_by(PentestSession.id)
                .order_by(PentestSession.created_at.desc())
                .limit(limit)
                .all()
            )
            return [(sess, count) for sess, count in rows]
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

    def persist_stage_findings(
        self,
        session_id: str,
        target_input: str,
        stage: str,
        parsed_findings: list[dict[str, Any]],
    ) -> int:
        """Convert and persist all findings from a stage. Returns count stored."""
        rows = stage_to_findings(stage, parsed_findings)
        for row in rows:
            self.add_finding(
                session_id,
                target_input=target_input,
                finding_type=row["finding_type"],
                severity=row["severity"],
                title=row["title"],
                description=row.get("description", ""),
                evidence=row.get("evidence"),
            )
        return len(rows)

    def get_findings_for_target(
        self,
        session_id: str,
        target_input: str,
        *,
        finding_type: str | None = None,
    ) -> list[Finding]:
        """Return findings scoped to a specific target input string."""
        db: SASession = self._factory()
        try:
            tr = (
                db.query(TargetRecord)
                .filter_by(session_id=session_id, input=target_input)
                .first()
            )
            if tr is None:
                return []
            q = db.query(Finding).filter_by(session_id=session_id, target_id=str(tr.id))
            if finding_type:
                q = q.filter(Finding.finding_type == finding_type)
            return q.order_by(Finding.timestamp).all()
        finally:
            db.close()

    def get_findings(
        self,
        session_id: str,
        *,
        severity: str | None = None,
        finding_type: str | None = None,
    ) -> list[Finding]:
        db: SASession = self._factory()
        try:
            q = db.query(Finding).filter_by(session_id=session_id)
            if severity:
                q = q.filter(Finding.severity == severity)
            if finding_type:
                q = q.filter(Finding.finding_type == finding_type)
            return q.order_by(Finding.timestamp).all()
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
