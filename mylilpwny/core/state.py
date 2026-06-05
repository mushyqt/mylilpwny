from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TargetState(str, Enum):
    DISCOVERED = "discovered"
    SCANNED = "scanned"
    ENUMERATED = "enumerated"
    ANALYZED = "analyzed"
    EXPLOITED = "exploited"

    def can_transition_to(self, next_state: "TargetState") -> bool:
        order = list(TargetState)
        return order.index(next_state) == order.index(self) + 1


@dataclass
class Target:
    input: str
    ip: str | None = None
    hostname: str | None = None
    state: TargetState = TargetState.DISCOVERED
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state.value,
            "metadata": self.metadata,
        }
