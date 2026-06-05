from __future__ import annotations

import json
from typing import Any

from mylilpwny.agent.types import AgentContext
from mylilpwny.core.pipeline import STAGE_ORDER
from mylilpwny.persistence.session import SessionManager

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def build_agent_context(
    sm: SessionManager,
    session_id: str,
    *,
    objective: str = "full-recon",
    current_target: str | None = None,
    history: list[Any] | None = None,
    memory_notes: list[str] | None = None,
    token_budget: int = 8000,
) -> AgentContext:
    """Fetch session data and return an AgentContext within the token budget."""
    sess = sm.get_session(session_id)
    scope: list[str] = list(sess.scope) if sess and sess.scope else []

    targets_raw = sm.get_targets(session_id)
    targets = [
        {"input": t.input, "ip": t.ip, "hostname": t.hostname, "state": t.state}
        for t in targets_raw
    ]

    findings_raw = sm.get_findings(session_id)
    findings_raw.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))

    findings: list[dict[str, Any]] = [
        {
            "finding_type": f.finding_type,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
        }
        for f in findings_raw
    ]

    # Trim findings to stay within token budget (reserve 2k tokens for overhead)
    findings_budget = token_budget - 2000
    kept: list[dict[str, Any]] = []
    used = 0
    for finding in findings:
        cost = _estimate_tokens(json.dumps(finding))
        if used + cost > findings_budget:
            break
        kept.append(finding)
        used += cost

    # Derive which pipeline stages have already completed for this target
    completed_stages: list[str] = []
    if current_target:
        completed_stages = sm.get_completed_stages(session_id, current_target)

    return AgentContext(
        session_id=session_id,
        objective=objective,
        scope=scope,
        targets=targets,
        findings=kept,
        history=list(history) if history else [],
        current_target=current_target,
        token_budget=token_budget,
        completed_stages=completed_stages,
        memory_notes=list(memory_notes) if memory_notes else [],
    )
