from __future__ import annotations

import json
from typing import Any

from mylilpwny.agent.types import AgentContext, ToolSchema

_STAGE_ORDER = ["recon", "portscan", "servicenum", "vulnanalysis"]

_SYSTEM_HEADER = """\
You are an expert penetration tester operating inside an automated security \
testing framework. You decide the next action to take against a target.

## Rules — NEVER violate these

1. Only act on targets explicitly listed in the scope.
2. Set confidence < 0.5 and risk_assessment high/critical when human review is warranted.
3. Prefer low-risk information-gathering before any active or destructive action.
4. Every response MUST be a single valid JSON object — no prose, no markdown fences.

## Output format

  "reasoning": "<step-by-step thinking about current state and what to do next>",
  "tool_name": "<exact tool name from the list, or done>",
  "parameters": {"target": "<ip or hostname>"},
  "confidence": 0.8,
  "risk_assessment": "low",
  "done": false

Set done=true and tool_name=done when the objective is complete or you are stuck.

## Progression rules

- Follow this order: recon → portscan → servicenum → vulnanalysis → done.
- NEVER call a stage that is already listed under "Completed stages" below.
- If all stages are complete, call done.\
"""


def build_system_prompt(
    context: AgentContext,
    available_tools: list[ToolSchema],
) -> str:
    tools_json = json.dumps([t.to_dict() for t in available_tools], indent=2)
    scope_str = "\n".join(f"- {s}" for s in context.scope) or "- (none specified)"
    return "\n\n".join([
        _SYSTEM_HEADER,
        f"## Available tools\n\n{tools_json}",
        f"## Scope\n\n{scope_str}",
        f"## Objective\n\n{context.objective}",
    ])


def build_user_message(context: AgentContext) -> str:
    parts: list[str] = []

    if context.current_target:
        parts.append(f"## Current target\n{context.current_target}")

    # Pipeline progress — this is the primary fix for stage repetition
    completed = context.completed_stages
    remaining = [s for s in _STAGE_ORDER if s not in completed]
    if completed or remaining:
        parts.append(
            f"## Pipeline progress\n"
            f"Completed : {', '.join(completed) if completed else 'none'}\n"
            f"Remaining : {', '.join(remaining) if remaining else 'none — call done'}"
        )

    # Findings
    if context.findings:
        by_sev: dict[str, list[Any]] = {}
        for f in context.findings:
            by_sev.setdefault(f.get("severity", "info"), []).append(f)

        lines: list[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            group = by_sev.get(sev, [])
            if group:
                lines.append(f"\n### {sev.capitalize()} ({len(group)})")
                for f in group[:8]:
                    lines.append(f"- [{f.get('finding_type')}] {f.get('title')}")
                if len(group) > 8:
                    lines.append(f"  … and {len(group) - 8} more")
        parts.append("## Current findings\n" + "\n".join(lines))
    else:
        parts.append("## Current findings\nNone yet.")

    # Memory notes (TASK-034)
    if context.memory_notes:
        parts.append("## Agent notes\n" + "\n".join(f"- {n}" for n in context.memory_notes))

    # Action history
    if context.history:
        lines = []
        for i, a in enumerate(context.history[-8:], 1):
            status = "BLOCKED" if "BLOCKED" in a.reasoning else "done" if a.done else "executed"
            lines.append(
                f"{i}. [{status}] {a.tool_name}  confidence={a.confidence:.2f}  risk={a.risk_assessment}"
            )
            if a.reasoning and status == "executed":
                lines.append(f"   → {a.reasoning[:120]}")
        parts.append("## Action history\n" + "\n".join(lines))

    if remaining:
        parts.append(f"Next required stage: **{remaining[0]}**\nWhat is your action?")
    else:
        parts.append("All stages complete. Call done.")

    return "\n\n".join(parts)
