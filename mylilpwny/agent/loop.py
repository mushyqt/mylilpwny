from __future__ import annotations

import asyncio
from typing import Any

from mylilpwny.agent.context import build_agent_context
from mylilpwny.agent.providers.base import LLMProvider
from mylilpwny.agent.tool_registry import get_all_tools
from mylilpwny.agent.types import AgentAction, AgentContext
from mylilpwny.core.orchestrator import Orchestrator
from mylilpwny.logging import get_logger
from mylilpwny.persistence.session import SessionManager

log = get_logger(__name__)

_STAGE_TOOLS = {"recon", "portscan", "servicenum", "vulnanalysis"}

# Tool name → pipeline stage mapping
_TOOL_TO_STAGE: dict[str, str] = {
    "recon": "recon",
    "portscan": "portscan",
    "servicenum": "servicenum",
    "vulnanalysis": "vulnanalysis",
}


class AgentLoop:
    """ReAct (Reason → Act) agent loop.

    Observe  → Think (LLM) → Act (Orchestrator) → repeat.
    """

    def __init__(
        self,
        provider: LLMProvider,
        orchestrator: Orchestrator,
        session_manager: SessionManager,
        *,
        max_iterations: int = 20,
        high_risk_threshold: str = "high",  # pause at this level and above
    ) -> None:
        self._provider = provider
        self._orchestrator = orchestrator
        self._sm = session_manager
        self._max_iterations = max_iterations
        self._high_risk_threshold = high_risk_threshold
        self._risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def _is_high_risk(self, action: AgentAction) -> bool:
        threshold = self._risk_order.get(self._high_risk_threshold, 2)
        return self._risk_order.get(action.risk_assessment, 0) >= threshold

    async def run(
        self,
        session_id: str,
        target: str,
        *,
        objective: str = "full-recon",
        dry_run: bool = False,
    ) -> list[AgentAction]:
        """Run the ReAct loop for a given target. Returns the action history."""
        tools = get_all_tools()
        history: list[AgentAction] = []

        log.info("agent loop started", target=target, objective=objective, dry_run=dry_run)

        for iteration in range(1, self._max_iterations + 1):
            log.debug("agent iteration", n=iteration, target=target)

            # Observe: build context from DB state
            ctx = build_agent_context(
                self._sm,
                session_id,
                objective=objective,
                current_target=target,
                history=history,
            )

            # Think: ask LLM for next action
            action = await self._provider.plan_next_action(ctx, tools)
            history.append(action)

            log.info(
                "agent decided",
                iteration=iteration,
                tool=action.tool_name,
                confidence=f"{action.confidence:.2f}",
                risk=action.risk_assessment,
                done=action.done,
            )

            # Terminate conditions
            if action.done or action.tool_name == "done":
                log.info("agent loop complete", iterations=iteration, target=target)
                break

            # High-risk gate: log a warning (human gate in TASK-038 will add interactivity)
            if self._is_high_risk(action):
                log.warning(
                    "high-risk action skipped — human confirmation required",
                    tool=action.tool_name,
                    risk=action.risk_assessment,
                )
                # Record the skip in history so the LLM knows it was blocked
                history.append(AgentAction(
                    tool_name=action.tool_name,
                    parameters=action.parameters,
                    reasoning="BLOCKED: high-risk action requires human confirmation.",
                    confidence=0.0,
                    risk_assessment=action.risk_assessment,
                    done=False,
                ))
                continue

            # Act: execute through orchestrator
            if not dry_run and action.tool_name in _TOOL_TO_STAGE:
                stage = _TOOL_TO_STAGE[action.tool_name]
                act_target = action.parameters.get("target", target)
                log.info("agent executing stage", stage=stage, target=act_target)
                try:
                    await self._orchestrator.run(
                        act_target,
                        stages=[stage],
                        session_id=session_id,
                    )
                except Exception as exc:
                    log.warning("stage execution failed", stage=stage, error=str(exc))
            elif dry_run:
                log.info(
                    "dry-run: would execute",
                    tool=action.tool_name,
                    params=action.parameters,
                )
            else:
                log.warning("unknown tool requested by agent", tool=action.tool_name)

        else:
            log.warning("agent loop hit max iterations", max=self._max_iterations)

        return history


async def run_agent(
    provider: LLMProvider,
    orchestrator: Orchestrator,
    session_manager: SessionManager,
    session_id: str,
    target: str,
    *,
    objective: str = "full-recon",
    dry_run: bool = False,
    max_iterations: int = 20,
) -> list[AgentAction]:
    """Convenience wrapper that creates and runs an AgentLoop."""
    loop = AgentLoop(
        provider=provider,
        orchestrator=orchestrator,
        session_manager=session_manager,
        max_iterations=max_iterations,
    )
    return await loop.run(
        session_id,
        target,
        objective=objective,
        dry_run=dry_run,
    )
