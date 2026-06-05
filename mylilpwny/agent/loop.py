from __future__ import annotations

from mylilpwny.agent import risk as risk_mod
from mylilpwny.agent.context import build_agent_context
from mylilpwny.agent.gate import ConfirmationGate
from mylilpwny.agent.knowledge import KnowledgeBase
from mylilpwny.agent.memory import AgentMemory
from mylilpwny.agent.providers.base import LLMProvider
from mylilpwny.agent.tool_registry import get_all_tools
from mylilpwny.agent.types import AgentAction, AgentContext
from mylilpwny.core.orchestrator import Orchestrator
from mylilpwny.logging import get_logger
from mylilpwny.persistence.session import SessionManager

log = get_logger(__name__)

_PIPELINE_TOOLS = {"recon", "portscan", "servicenum", "vulnanalysis"}
_META_TOOLS = {"remember", "query_memory", "done"}


class AgentLoop:
    """ReAct (Reason → Act) agent loop — Sprint 7 complete.

    Observe → Think (LLM) → [Gate] → Act (Orchestrator / memory) → repeat.
    """

    def __init__(
        self,
        provider: LLMProvider,
        orchestrator: Orchestrator,
        session_manager: SessionManager,
        *,
        max_iterations: int = 20,
        mode: str = "semi-auto",
        dry_run: bool = False,
    ) -> None:
        self._provider = provider
        self._orchestrator = orchestrator
        self._sm = session_manager
        self._max_iterations = max_iterations
        self._gate = ConfirmationGate(mode=mode, dry_run=dry_run)
        self._dry_run = dry_run

    async def run(
        self,
        session_id: str,
        target: str,
        *,
        objective: str = "full-recon",
    ) -> list[AgentAction]:
        """Run the ReAct loop. Returns the full action history."""
        tools = get_all_tools()
        history: list[AgentAction] = []
        memory = AgentMemory()                    # TASK-034: short-term memory
        kb = KnowledgeBase(self._sm)              # TASK-035 + 036: knowledge base

        log.info("agent loop started", target=target, objective=objective, dry_run=self._dry_run)

        for iteration in range(1, self._max_iterations + 1):
            log.debug("agent iteration", n=iteration, target=target)

            # --- Observe ---
            ctx = build_agent_context(
                self._sm,
                session_id,
                objective=objective,
                current_target=target,
                history=history,
                memory_notes=memory.snapshot(),
            )

            # --- Think ---
            action = await self._provider.plan_next_action(ctx, tools)

            # --- TASK-037: Risk classifier override ---
            effective_risk = risk_mod.classify(action)
            if effective_risk != action.risk_assessment:
                log.debug("risk reclassified", tool=action.tool_name,
                          llm=action.risk_assessment, effective=effective_risk)
                action = AgentAction(
                    tool_name=action.tool_name,
                    parameters=action.parameters,
                    reasoning=action.reasoning,
                    confidence=action.confidence,
                    risk_assessment=effective_risk,
                    done=action.done,
                )

            history.append(action)
            log.info(
                "agent decided",
                iteration=iteration,
                tool=action.tool_name,
                confidence=f"{action.confidence:.2f}",
                risk=effective_risk,
                done=action.done,
            )

            # --- Terminate ---
            if action.done or action.tool_name == "done":
                log.info("agent loop complete", iterations=iteration, target=target)
                break

            # --- TASK-038: Confirmation gate ---
            if self._gate.requires_confirmation(action, effective_risk):
                decision = self._gate.request_confirmation(action, effective_risk)
                if decision == "abort":
                    log.warning("agent loop aborted by user", iteration=iteration)
                    history.append(_blocked(action, "ABORTED by user."))
                    break
                if decision == "skip":
                    log.info("action skipped by user", tool=action.tool_name)
                    history.append(_blocked(action, "SKIPPED by user."))
                    continue

            # --- Act ---
            if action.tool_name == "remember":
                # TASK-034: store note in short-term memory
                note = action.parameters.get("note", "")
                if note:
                    memory.add(note)
                    log.info("agent remembered", note=note[:80])

            elif action.tool_name == "query_memory":
                # TASK-035: query knowledge base and inject result as a note
                query = action.parameters.get("query", "")
                if query:
                    result = kb.query(query)
                    memory.add(f"[KB] {result[:300]}")
                    log.info("agent queried KB", query=query)

            elif action.tool_name in _PIPELINE_TOOLS:
                act_target = action.parameters.get("target", target)
                if self._dry_run:
                    log.info("dry-run: would execute", tool=action.tool_name, target=act_target)
                else:
                    log.info("agent executing stage", stage=action.tool_name, target=act_target)
                    try:
                        await self._orchestrator.run(
                            act_target,
                            stages=[action.tool_name],
                            session_id=session_id,
                        )
                    except Exception as exc:
                        log.warning("stage execution failed", stage=action.tool_name, error=str(exc))

            else:
                log.warning("unknown tool — skipping", tool=action.tool_name)

        else:
            log.warning("agent loop hit max iterations", max=self._max_iterations)

        return history


def _blocked(action: AgentAction, reason: str) -> AgentAction:
    return AgentAction(
        tool_name=action.tool_name,
        parameters=action.parameters,
        reasoning=reason,
        confidence=0.0,
        risk_assessment=action.risk_assessment,
        done=False,
    )


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
    mode: str = "semi-auto",
) -> list[AgentAction]:
    loop = AgentLoop(
        provider=provider,
        orchestrator=orchestrator,
        session_manager=session_manager,
        max_iterations=max_iterations,
        mode=mode,
        dry_run=dry_run,
    )
    return await loop.run(session_id, target, objective=objective)
