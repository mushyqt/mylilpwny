from __future__ import annotations

import json
from typing import Any

from mylilpwny.agent.types import AgentContext
from mylilpwny.persistence.session import SessionManager


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return max(1, len(text) // 4)


def build_agent_context(
    sm: SessionManager,
    session_id: str,
    *,
    objective: str = "full-recon",
    current_target: str | None = None,
    history: list[Any] | None = None,
    token_budget: int = 8000,
) -> AgentContext:
    """Fetch session data and return an AgentContext within the token budget.

    Findings are truncated (oldest info-level dropped first) if the serialised
    context would exceed token_budget.
    """
    sess = sm.get_session(session_id)
    scope: list[str] = list(sess.scope) if sess and sess.scope else []

    targets_raw = sm.get_targets(session_id)
    targets = [
        {
            "input": t.input,
            "ip": t.ip,
            "hostname": t.hostname,
            "state": t.state,
        }
        for t in targets_raw
    ]

    findings_raw = sm.get_findings(session_id)
    # Sort: critical/high first so we keep the most relevant under budget
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_raw.sort(key=lambda f: _sev_order.get(f.severity, 99))

    findings: list[dict[str, Any]] = [
        {
            "finding_type": f.finding_type,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
        }
        for f in findings_raw
    ]

    # Trim findings to stay within token budget
    # Reserve ~2000 tokens for system prompt + user message overhead
    findings_budget = token_budget - 2000
    kept: list[dict[str, Any]] = []
    used = 0
    for finding in findings:
        cost = _estimate_tokens(json.dumps(finding))
        if used + cost > findings_budget:
            break
        kept.append(finding)
        used += cost

    return AgentContext(
        session_id=session_id,
        objective=objective,
        scope=scope,
        targets=targets,
        findings=kept,
        history=list(history) if history else [],
        current_target=current_target,
        token_budget=token_budget,
    )
