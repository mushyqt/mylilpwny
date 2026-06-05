"""TASK-037: Deterministic risk classifier.

Validates and overrides the LLM's risk_assessment for known tools.
The LLM's assessment is trusted for unknown/plugin tools.
"""
from __future__ import annotations

from typing import Literal

from mylilpwny.agent.types import AgentAction

RiskLevel = Literal["low", "medium", "high", "critical"]

_RISK_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Authoritative risk levels for built-in pipeline tools.
# LLM cannot downgrade these.
_TOOL_FLOOR: dict[str, RiskLevel] = {
    "recon": "low",
    "portscan": "medium",
    "servicenum": "low",
    "vulnanalysis": "low",
    "remember": "low",
    "query_memory": "low",
    "done": "low",
}

# These tools always run at exactly this level (LLM cannot upgrade either).
_TOOL_CEILING: dict[str, RiskLevel] = {
    "recon": "low",
    "remember": "low",
    "query_memory": "low",
    "done": "low",
}


def classify(action: AgentAction) -> RiskLevel:
    """Return the effective risk level for an action.

    For known passive tools the classification is deterministic.
    For unknown/plugin tools the LLM's assessment is used as-is.
    """
    tool = action.tool_name
    llm_risk = action.risk_assessment

    # Enforce ceiling for fully-passive tools
    ceiling = _TOOL_CEILING.get(tool)
    if ceiling is not None:
        return ceiling

    # Enforce minimum floor for tools with known risk profiles
    floor = _TOOL_FLOOR.get(tool)
    if floor is not None:
        llm_order = _RISK_ORDER.get(llm_risk, 0)
        floor_order = _RISK_ORDER[floor]
        return llm_risk if llm_order >= floor_order else floor  # type: ignore[return-value]

    # Unknown tool — trust the LLM
    return llm_risk  # type: ignore[return-value]


def exceeds_threshold(risk: RiskLevel, threshold: RiskLevel) -> bool:
    return _RISK_ORDER.get(risk, 0) >= _RISK_ORDER.get(threshold, 2)
