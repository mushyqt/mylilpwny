"""TASK-035 + TASK-036: Knowledge base for medium and long-term memory."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mylilpwny.persistence.session import SessionManager

_SEED_PATH = Path(__file__).parent.parent / "data" / "knowledge_seed.json"

_seed_cache: list[dict[str, Any]] | None = None


def _load_seed() -> list[dict[str, Any]]:
    global _seed_cache
    if _seed_cache is None:
        try:
            _seed_cache = json.loads(_SEED_PATH.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            _seed_cache = []
    return _seed_cache


class KnowledgeBase:
    """Query interface for static and session-derived knowledge.

    - Static knowledge: seeded from knowledge_seed.json (common CVEs/techniques).
    - Dynamic knowledge: cross-session vulnerability findings stored in the DB.
    """

    def __init__(self, session_manager: SessionManager) -> None:
        self._sm = session_manager

    def query(self, query: str, *, limit: int = 5) -> str:
        """Return a formatted string of relevant knowledge for a query.

        Searches static seed entries and historical DB findings.
        """
        q_lower = query.lower()
        results: list[str] = []

        # --- Static seed entries ---
        seed = _load_seed()
        for entry in seed:
            svc = str(entry.get("service", "")).lower()
            ver = str(entry.get("version_pattern", "")).lower()
            cve = str(entry.get("cve") or "").lower()
            if any(term in q_lower for term in [svc, ver, cve] if term):
                cve_str = entry.get("cve") or "no CVE"
                sev = entry.get("severity", "unknown")
                technique = entry.get("technique", "")
                notes = entry.get("notes", "")
                results.append(
                    f"[{sev.upper()}] {entry.get('service')} {entry.get('version_pattern')} "
                    f"— {cve_str}\n  Technique: {technique}\n  Notes: {notes}"
                )
                if len(results) >= limit:
                    break

        # --- Cross-session DB findings ---
        if len(results) < limit:
            db_findings = self._sm.get_cross_session_findings(query, limit=limit - len(results))
            for f in db_findings:
                results.append(
                    f"[DB/{f.severity.upper()}] {f.title}\n"
                    f"  Evidence: {json.dumps(f.evidence, default=str)[:120]}"
                )

        if not results:
            return f"No knowledge found for: {query!r}"

        return f"Knowledge for {query!r}:\n\n" + "\n\n".join(results)
