from __future__ import annotations

from typing import Protocol, runtime_checkable

from mylilpwny.agent.types import AgentAction, AgentContext, ToolSchema


@runtime_checkable
class LLMProvider(Protocol):
    """Provider-agnostic interface for LLM-backed planning."""

    async def plan_next_action(
        self,
        context: AgentContext,
        available_tools: list[ToolSchema],
    ) -> AgentAction:
        """Given context and available tools, return the next action to take."""
        ...

    async def is_available(self) -> bool:
        """Return True if the provider backend is reachable."""
        ...
