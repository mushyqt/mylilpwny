from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class ToolSchema:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema object
    risk_level: Literal["low", "medium", "high", "critical"] = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "risk_level": self.risk_level,
        }


@dataclass
class AgentAction:
    tool_name: str
    parameters: dict[str, Any]
    reasoning: str
    confidence: float  # 0.0–1.0
    risk_assessment: Literal["low", "medium", "high", "critical"]
    done: bool = False  # True when agent signals objective complete

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0–1.0, got {self.confidence}")


@dataclass
class AgentContext:
    session_id: str
    objective: str
    scope: list[str]
    targets: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    history: list[AgentAction] = field(default_factory=list)
    current_target: str | None = None
    token_budget: int = 8000
