from __future__ import annotations

import json
import re
from typing import Any

import httpx

from mylilpwny.agent.prompts import build_system_prompt, build_user_message
from mylilpwny.agent.types import AgentAction, AgentContext, ToolSchema
from mylilpwny.logging import get_logger

log = get_logger(__name__)

_DEFAULT_BASE_URL = "http://localhost:11434"
_DEFAULT_MODEL = "llama3.1"
_DEFAULT_TIMEOUT = 120.0

# Fallback action when the LLM response can't be parsed
_PARSE_FAILURE_ACTION = AgentAction(
    tool_name="done",
    parameters={},
    reasoning="LLM response could not be parsed — aborting loop to avoid undefined behaviour.",
    confidence=0.0,
    risk_assessment="low",
    done=True,
)


def _extract_json(text: str) -> dict[str, Any]:
    """Extract the first JSON object from text, handling markdown fences."""
    # Strip common markdown code fences
    text = re.sub(r"```(?:json)?\s*", "", text).strip()
    # Find the outermost {...}
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in response")
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : i + 1])  # type: ignore[no-any-return]
    raise ValueError("Unterminated JSON object in response")


def _parse_action(raw: dict[str, Any]) -> AgentAction:
    tool_name = str(raw.get("tool_name", "done"))
    done = bool(raw.get("done", tool_name == "done"))
    confidence = float(raw.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))
    risk = str(raw.get("risk_assessment", "low"))
    if risk not in ("low", "medium", "high", "critical"):
        risk = "low"
    return AgentAction(
        tool_name=tool_name,
        parameters=dict(raw.get("parameters", {})),
        reasoning=str(raw.get("reasoning", "")),
        confidence=confidence,
        risk_assessment=risk,  # type: ignore[arg-type]
        done=done,
    )


class OllamaProvider:
    """LLM provider backed by a local Ollama instance."""

    def __init__(
        self,
        base_url: str = _DEFAULT_BASE_URL,
        model: str = _DEFAULT_MODEL,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{self._base_url}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    async def plan_next_action(
        self,
        context: AgentContext,
        available_tools: list[ToolSchema],
    ) -> AgentAction:
        system_prompt = build_system_prompt(context, available_tools)
        user_message = build_user_message(context)

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            "format": "json",  # Ollama structured output — forces valid JSON
            "options": {
                "temperature": 0.2,  # low temp for more deterministic tool calls
                "num_predict": 1024,
            },
        }

        log.debug("ollama request", model=self._model, target=context.current_target)

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._base_url}/api/chat",
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            log.warning("ollama request failed", error=str(exc))
            return _PARSE_FAILURE_ACTION

        content = body.get("message", {}).get("content", "")
        log.debug("ollama response", content_len=len(content))

        try:
            raw = _extract_json(content)
            action = _parse_action(raw)
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            log.warning("ollama response parse failed", error=str(exc), content=content[:200])
            return _PARSE_FAILURE_ACTION

        log.info(
            "agent action",
            tool=action.tool_name,
            confidence=action.confidence,
            risk=action.risk_assessment,
            done=action.done,
        )
        return action
