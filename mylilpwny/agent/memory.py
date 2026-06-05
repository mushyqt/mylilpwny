"""TASK-034: Short-term in-session memory for the agent."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentMemory:
    """In-memory store that lives for the duration of a single agent loop run.

    Notes are injected into every LLM prompt so the agent can reference
    observations made in previous iterations of the same session.
    """

    notes: list[str] = field(default_factory=list)
    max_notes: int = 50

    def add(self, note: str) -> None:
        """Store a new observation. Deduplicated by exact text. Oldest evicted when cap reached."""
        stripped = note.strip()
        if not stripped or stripped in self.notes:
            return
        if len(self.notes) >= self.max_notes:
            self.notes.pop(0)
        self.notes.append(stripped)

    def clear(self) -> None:
        self.notes.clear()

    def snapshot(self) -> list[str]:
        return list(self.notes)
