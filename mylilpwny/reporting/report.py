from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment

from mylilpwny.persistence.session import SessionManager

# Severity order for sorting/display
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

_MARKDOWN_TEMPLATE = """\
# Pentest Report — {{ session_id }}

**Generated:** {{ generated_at }}
**Status:** {{ status }}
**Objective:** {{ objective or "general" }}
**Scope:** {{ scope | join(", ") or "—" }}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Targets scanned | {{ stats.targets }} |
| Open ports found | {{ stats.open_ports }} |
| Services identified | {{ stats.services }} |
| Vulnerabilities | 🔴 {{ stats.critical }} critical / 🟠 {{ stats.high }} high / 🟡 {{ stats.medium }} medium / 🔵 {{ stats.low }} low |

---

## Targets

{% for t in targets %}
### {{ t.input }}

- **IP:** {{ t.ip or "—" }}
- **Hostname:** {{ t.hostname or "—" }}
- **State:** {{ t.state }}

{% endfor %}

---

## Findings by Severity

{% for sev in ["critical", "high", "medium", "low", "info"] %}
{% set sev_findings = findings | selectattr("severity", "equalto", sev) | list %}
{% if sev_findings %}
### {{ sev | capitalize }} ({{ sev_findings | length }})

{% for f in sev_findings %}
#### {{ f.title }}

- **Type:** {{ f.finding_type }}
- **Target:** {{ f.target or "—" }}
- **Timestamp:** {{ f.timestamp }}
{% if f.description %}
- **Description:** {{ f.description }}
{% endif %}
{% if f.evidence %}

<details><summary>Evidence</summary>

```json
{{ f.evidence | tojson(indent=2) }}
```

</details>
{% endif %}

---
{% endfor %}
{% endif %}
{% endfor %}

## Tool Run Timeline

| Time | Target | Module | Status | Duration |
|------|--------|--------|--------|----------|
{% for r in tool_runs %}
| {{ r.timestamp }} | {{ r.target }} | {{ r.module }} | {{ r.status }} | {{ "%.2f" | format(r.duration) }}s |
{% endfor %}
"""


@dataclass
class ReportData:
    session_id: str
    created_at: datetime | None
    status: str
    scope: list[str]
    objective: str | None
    targets: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    tool_runs: list[dict[str, Any]]

    @property
    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "targets": len(self.targets),
            "open_ports": sum(1 for f in self.findings if f.get("finding_type") == "open_port"),
            "services": sum(1 for f in self.findings if f.get("finding_type") == "service"),
            **counts,
        }

    @property
    def findings_by_severity(self) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {s: [] for s in _SEVERITY_ORDER}
        for f in self.findings:
            sev = f.get("severity", "info")
            result.setdefault(sev, []).append(f)
        return result


def build_report_data(sm: SessionManager, session_id: str) -> ReportData:
    """Fetch session data from DB and return a ReportData object."""
    sess = sm.get_session(session_id)
    if sess is None:
        raise ValueError(f"Session not found: {session_id}")

    targets_raw = sm.get_targets(session_id)
    findings_raw = sm.get_findings(session_id)
    tool_runs_raw = sm.get_tool_runs(session_id)

    # Build a target_id → input lookup for denormalising findings
    target_map: dict[str, str] = {str(t.id): t.input for t in targets_raw}

    targets = [
        {
            "input": t.input,
            "ip": t.ip,
            "hostname": t.hostname,
            "state": t.state,
        }
        for t in targets_raw
    ]

    findings = sorted(
        [
            {
                "id": str(f.id),
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "target": target_map.get(str(f.target_id)) if f.target_id else None,
                "timestamp": f.timestamp.strftime("%Y-%m-%d %H:%M:%S") if f.timestamp else None,
            }
            for f in findings_raw
        ],
        key=lambda x: _SEVERITY_ORDER.get(str(x["severity"]), 99),
    )

    tool_runs = [
        {
            "timestamp": r.timestamp.strftime("%H:%M:%S") if r.timestamp else "—",
            "target": r.target,
            "module": r.module,
            "command": r.command,
            "exit_code": r.exit_code,
            "duration": r.duration,
            "status": r.status,
        }
        for r in tool_runs_raw
    ]

    return ReportData(
        session_id=session_id,
        created_at=sess.created_at,
        status=sess.status,
        scope=list(sess.scope) if sess.scope else [],
        objective=sess.objective,
        targets=targets,
        findings=findings,
        tool_runs=tool_runs,
    )


def to_json(data: ReportData, indent: int = 2) -> str:
    """Serialise ReportData to a JSON string."""
    return json.dumps(
        {
            "session_id": data.session_id,
            "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
            "created_at": data.created_at.isoformat() if data.created_at else None,
            "status": data.status,
            "scope": data.scope,
            "objective": data.objective,
            "stats": data.stats,
            "targets": data.targets,
            "findings": data.findings,
            "tool_runs": data.tool_runs,
        },
        indent=indent,
        default=str,
    )


def to_markdown(data: ReportData) -> str:
    """Render ReportData as a Markdown string using Jinja2."""
    env = Environment(autoescape=False)
    env.filters["tojson"] = lambda v, indent=2: json.dumps(v, indent=indent, default=str)
    template = env.from_string(_MARKDOWN_TEMPLATE)
    return template.render(
        session_id=data.session_id,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        status=data.status,
        scope=data.scope,
        objective=data.objective,
        targets=data.targets,
        findings=data.findings,
        tool_runs=data.tool_runs,
        stats=data.stats,
    )


def console_summary(data: ReportData) -> str:
    """Return a compact plain-text summary for console display after a run."""
    s = data.stats
    vuln_parts = [
        f"{_SEVERITY_EMOJI[sev]} {s[sev]} {sev}"
        for sev in ("critical", "high", "medium", "low")
        if s[sev] > 0
    ]
    vulns = "  ".join(vuln_parts) if vuln_parts else "none"
    lines = [
        f"Targets  : {s['targets']}",
        f"Ports    : {s['open_ports']} open",
        f"Services : {s['services']}",
        f"Vulns    : {vulns}",
    ]
    return "\n".join(lines)
