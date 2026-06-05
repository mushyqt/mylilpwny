from __future__ import annotations

from mylilpwny.agent.types import ToolSchema

# Canonical tool schemas for the built-in pipeline stages.
# Each schema describes what the LLM can ask the orchestrator to do.

_BUILTIN_SCHEMAS: list[ToolSchema] = [
    ToolSchema(
        name="recon",
        description=(
            "DNS resolution, WHOIS, ASN lookup, and subdomain enumeration for a target. "
            "Low-risk, purely passive/informational."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, hostname, or domain to recon"},
            },
            "required": ["target"],
        },
        risk_level="low",
    ),
    ToolSchema(
        name="portscan",
        description=(
            "Full port sweep (masscan + nmap). Identifies all open TCP/UDP ports on the target."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "ports": {
                    "type": "string",
                    "description": "Port range, e.g. '1-65535' or '80,443,8080'",
                    "default": "1-65535",
                },
            },
            "required": ["target"],
        },
        risk_level="medium",
    ),
    ToolSchema(
        name="servicenum",
        description=(
            "Service and version detection on discovered open ports using nmap -sV -sC "
            "and targeted NSE scripts."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Specific ports to enumerate (empty = use portscan results)",
                },
            },
            "required": ["target"],
        },
        risk_level="low",
    ),
    ToolSchema(
        name="vulnanalysis",
        description=(
            "Vulnerability analysis: searchsploit + NVD CVE lookup for detected services. "
            "Purely informational — no exploitation."
        ),
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
            },
            "required": ["target"],
        },
        risk_level="low",
    ),
    ToolSchema(
        name="remember",
        description=(
            "Store a short observation or hypothesis for this session. "
            "Use it to note interesting findings, credential hints, or next ideas. "
            "Notes are shown in every subsequent prompt."
        ),
        parameters={
            "type": "object",
            "properties": {
                "note": {"type": "string", "description": "The observation to remember (max 200 chars)"},
            },
            "required": ["note"],
        },
        risk_level="low",
    ),
    ToolSchema(
        name="query_memory",
        description=(
            "Search the knowledge base and historical findings for a service, version, or CVE. "
            "Use before vulnanalysis to check if known exploits exist."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Service name, version string, or CVE ID"},
            },
            "required": ["query"],
        },
        risk_level="low",
    ),
    ToolSchema(
        name="done",
        description="Signal that the objective is complete or the agent is unable to proceed.",
        parameters={
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Brief summary of what was accomplished"},
            },
            "required": ["summary"],
        },
        risk_level="low",
    ),
]

# Map tool name → schema for O(1) lookup
_REGISTRY: dict[str, ToolSchema] = {s.name: s for s in _BUILTIN_SCHEMAS}


def get_all_tools() -> list[ToolSchema]:
    """Return all registered tool schemas."""
    return list(_REGISTRY.values())


def get_tool(name: str) -> ToolSchema | None:
    return _REGISTRY.get(name)


def register_tool(schema: ToolSchema) -> None:
    """Register an additional tool schema (e.g. from a plugin)."""
    _REGISTRY[schema.name] = schema
