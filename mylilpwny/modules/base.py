from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from mylilpwny.core.state import Target


@dataclass
class ModuleResult:
    status: Literal["success", "error", "skipped"]
    raw_output: str
    parsed_findings: list[dict[str, Any]]
    duration: float
    command_run: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "raw_output": self.raw_output,
            "parsed_findings": self.parsed_findings,
            "duration": self.duration,
            "command_run": self.command_run,
            "error": self.error,
        }


class BaseModule(ABC):
    name: str
    description: str
    risk_level: Literal["low", "medium", "high", "critical"]

    @abstractmethod
    async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult: ...

    def validate_options(self, options: dict[str, Any]) -> bool:
        return True

    def check_dependencies(self) -> list[str]:
        """Return names of required tools that are not installed."""
        return []

    def _tool_available(self, tool: str) -> bool:
        return shutil.which(tool) is not None
