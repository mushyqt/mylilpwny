from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from mylilpwny.modules.portscan import OpenPort
    from mylilpwny.modules.servicenum import Service
    from mylilpwny.modules.webnum import WebFingerprint
    from mylilpwny.modules.vulnanalysis import Vulnerability


class InvalidStateTransitionError(Exception):
    pass


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
    ports: list[Any] = field(default_factory=list)        # list[OpenPort]
    services: list[Any] = field(default_factory=list)     # list[Service]
    web: list[Any] = field(default_factory=list)          # list[WebFingerprint]
    vulnerabilities: list[Any] = field(default_factory=list)  # list[Vulnerability]
    state: TargetState = field(default=TargetState.DISCOVERED)
    metadata: dict[str, Any] = field(default_factory=dict)

    def transition(self, next_state: TargetState) -> None:
        """Advance state. Raises InvalidStateTransitionError on invalid transition."""
        if not self.state.can_transition_to(next_state):
            raise InvalidStateTransitionError(
                f"Cannot transition from {self.state.value} to {next_state.value}"
            )
        self.state = next_state

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state.value,
            "ports": [p.to_dict() if hasattr(p, "to_dict") else p for p in self.ports],
            "services": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.services],
            "web": [w.to_dict() if hasattr(w, "to_dict") else w for w in self.web],
            "vulnerabilities": [v.to_dict() if hasattr(v, "to_dict") else v for v in self.vulnerabilities],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Target":
        state = TargetState(data.get("state", "discovered"))
        return cls(
            input=data["input"],
            ip=data.get("ip"),
            hostname=data.get("hostname"),
            ports=data.get("ports", []),
            services=data.get("services", []),
            web=data.get("web", []),
            vulnerabilities=data.get("vulnerabilities", []),
            state=state,
            metadata=data.get("metadata", {}),
        )
