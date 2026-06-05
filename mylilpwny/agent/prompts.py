from __future__ import annotations

import json
from typing import Any

from mylilpwny.agent.types import AgentContext, ToolSchema

_SYSTEM_HEADER = """\
You are an expert penetration tester and bug bounty hunter operating inside an \
automated security testing framework.

## Rules — NEVER violate these

1. Only act on targets explicitly listed in the scope. Refuse to act on anything else.
2. For actions rated high or critical risk, set confidence < 0.5 and explain why \
human review is needed.
3. Always prefer low-risk information-gathering before active exploitation.
4. Every response MUST be a single valid JSON object — no prose, no markdown fences.

## Output format

Respond with exactly this JSON structure (replace the angle-bracket placeholders):

  "reasoning": "<your step-by-step thinking>",
  "tool_name": "<tool name, or done when objective is complete>",
  "parameters": {},
  "confidence": 0.0,
  "risk_assessment": "low",
  "done": false

If the objective is complete or you are stuck, set tool_name to done and done to true.\
"""


def build_system_prompt(
    context: AgentContext,
    available_tools: list[ToolSchema],
) -> str:
    tools_json = json.dumps([t.to_dict() for t in available_tools], indent=2)
    scope_str = "\n".join(f"- {s}" for s in context.scope) or "- (none — all targets allowed)"
    return "\n\n".join([
        _SYSTEM_HEADER,
        f"## Available tools\n\n{tools_json}",
        f"## Scope\n\n{scope_str}",
        f"## Objective\n\n{context.objective}",
    ])


def build_user_message(context: AgentContext) -> str:
    """Compose the user-turn message from current context state."""
    parts: list[str] = []

    if context.current_target:
        parts.append(f"## Current target\n{context.current_target}")

    if context.targets:
        targets_text = "\n".join(
            f"- {t.get('input', '?')}  state={t.get('state', '?')}"
            for t in context.targets
        )
        parts.append(f"## Known targets\n{targets_text}")

    if context.findings:
        # Group by severity for compact display
        by_sev: dict[str, list[Any]] = {}
        for f in context.findings:
            by_sev.setdefault(f.get("severity", "info"), []).append(f)

        finding_lines: list[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            group = by_sev.get(sev, [])
            if group:
                finding_lines.append(f"\n### {sev.capitalize()} ({len(group)})")
                for f in group[:10]:  # cap per-severity to avoid blowing context
                    finding_lines.append(f"- [{f.get('finding_type')}] {f.get('title')}")
                if len(group) > 10:
                    finding_lines.append(f"  … and {len(group) - 10} more")
        parts.append("## Current findings\n" + "\n".join(finding_lines))
    else:
        parts.append("## Current findings\nNone yet.")

    if context.history:
        last = context.history[-1]
        parts.append(
            f"## Last action taken\n"
            f"tool={last.tool_name}  confidence={last.confidence:.2f}  "
            f"risk={last.risk_assessment}\n"
            f"reasoning: {last.reasoning}"
        )

    parts.append("What is the next action?")
    return "\n\n".join(parts)
