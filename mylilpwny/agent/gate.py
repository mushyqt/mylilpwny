"""TASK-038: Human confirmation gate for high-risk agent actions."""
from __future__ import annotations

from typing import Literal

from rich.console import Console
from rich.panel import Panel

from mylilpwny.agent.risk import RiskLevel, exceeds_threshold
from mylilpwny.agent.types import AgentAction

_console = Console()

GateDecision = Literal["proceed", "skip", "abort"]

# Risk threshold per operating mode
_MODE_THRESHOLD: dict[str, RiskLevel] = {
    "manual": "medium",      # confirm everything >= medium
    "semi-auto": "high",     # confirm >= high
    "autonomous": "critical", # confirm only critical
}


class ConfirmationGate:
    """Pauses before risky agent actions and asks for human input.

    In dry_run mode the gate is bypassed (actions are never executed anyway).
    """

    def __init__(self, mode: str = "semi-auto", *, dry_run: bool = False) -> None:
        self._threshold: RiskLevel = _MODE_THRESHOLD.get(mode, "high")  # type: ignore[assignment]
        self._dry_run = dry_run

    def requires_confirmation(self, action: AgentAction, effective_risk: RiskLevel) -> bool:
        if self._dry_run:
            return False
        return exceeds_threshold(effective_risk, self._threshold)

    def request_confirmation(self, action: AgentAction, effective_risk: RiskLevel) -> GateDecision:
        """Display risk info and prompt for human decision. Blocking."""
        _console.print(Panel(
            f"[bold red]High-risk action requested[/bold red]\n\n"
            f"Tool       : [cyan]{action.tool_name}[/cyan]\n"
            f"Risk       : [red]{effective_risk}[/red]\n"
            f"Parameters : {action.parameters}\n\n"
            f"Reasoning  : {action.reasoning[:300]}",
            title="⚠ Agent Gate",
            border_style="red",
        ))

        while True:
            try:
                raw = input("Proceed? [y=yes / s=skip / a=abort] > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return "abort"

            if raw in ("y", "yes"):
                return "proceed"
            if raw in ("s", "skip", "n", "no"):
                return "skip"
            if raw in ("a", "abort", "q", "quit"):
                return "abort"

            _console.print("[dim]Enter y, s, or a.[/dim]")
