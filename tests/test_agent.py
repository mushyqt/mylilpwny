"""Tests for the AI agent layer (TASK-028 through TASK-033)."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from mylilpwny.agent.context import build_agent_context
from mylilpwny.agent.loop import AgentLoop
from mylilpwny.agent.prompts import build_system_prompt, build_user_message
from mylilpwny.agent.providers.base import LLMProvider
from mylilpwny.agent.providers.ollama import OllamaProvider, _extract_json, _parse_action
from mylilpwny.agent.tool_registry import get_all_tools, get_tool, register_tool
from mylilpwny.agent.types import AgentAction, AgentContext, ToolSchema
from mylilpwny.persistence.db import setup_database
from mylilpwny.persistence.session import SessionManager


# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _sm() -> SessionManager:
    _, factory = setup_database(":memory:")
    return SessionManager(factory)


def _ctx(**kwargs: object) -> AgentContext:
    defaults: dict[str, object] = dict(
        session_id="s1",
        objective="full-recon",
        scope=["10.0.0.1"],
        targets=[{"input": "10.0.0.1", "state": "discovered"}],
        findings=[],
        history=[],
        current_target="10.0.0.1",
    )
    defaults.update(kwargs)
    return AgentContext(**defaults)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
#  TASK-028 — Types                                                            #
# --------------------------------------------------------------------------- #

class TestAgentTypes:
    def test_tool_schema_to_dict(self) -> None:
        ts = ToolSchema(name="foo", description="bar", parameters={"type": "object"})
        d = ts.to_dict()
        assert d["name"] == "foo"
        assert "parameters" in d

    def test_agent_action_confidence_clamp(self) -> None:
        with pytest.raises(ValueError):
            AgentAction(
                tool_name="recon",
                parameters={},
                reasoning="test",
                confidence=1.5,
                risk_assessment="low",
            )

    def test_agent_action_done_flag(self) -> None:
        a = AgentAction(
            tool_name="done",
            parameters={"summary": "all done"},
            reasoning="finished",
            confidence=1.0,
            risk_assessment="low",
            done=True,
        )
        assert a.done is True


# --------------------------------------------------------------------------- #
#  TASK-028 — Protocol structural check                                        #
# --------------------------------------------------------------------------- #

class TestLLMProviderProtocol:
    def test_ollama_satisfies_protocol(self) -> None:
        provider = OllamaProvider()
        assert isinstance(provider, LLMProvider)

    def test_mock_satisfies_protocol(self) -> None:
        class MockProvider:
            async def plan_next_action(self, context: AgentContext, available_tools: list[ToolSchema]) -> AgentAction:
                return AgentAction("done", {}, "done", 1.0, "low", done=True)

            async def is_available(self) -> bool:
                return True

        assert isinstance(MockProvider(), LLMProvider)


# --------------------------------------------------------------------------- #
#  TASK-029 — Ollama provider                                                  #
# --------------------------------------------------------------------------- #

class TestOllamaProvider:
    def test_extract_json_plain(self) -> None:
        text = '{"tool_name": "recon", "parameters": {}, "reasoning": "go", "confidence": 0.8, "risk_assessment": "low", "done": false}'
        result = _extract_json(text)
        assert result["tool_name"] == "recon"

    def test_extract_json_with_fence(self) -> None:
        text = "```json\n{\"tool_name\": \"portscan\", \"parameters\": {\"target\": \"1.2.3.4\"}, \"reasoning\": \"x\", \"confidence\": 0.7, \"risk_assessment\": \"medium\", \"done\": false}\n```"
        result = _extract_json(text)
        assert result["tool_name"] == "portscan"

    def test_extract_json_no_json_raises(self) -> None:
        with pytest.raises(ValueError):
            _extract_json("just some prose text")

    def test_parse_action_valid(self) -> None:
        raw = {
            "tool_name": "recon",
            "parameters": {"target": "10.0.0.1"},
            "reasoning": "start with recon",
            "confidence": 0.9,
            "risk_assessment": "low",
            "done": False,
        }
        action = _parse_action(raw)
        assert action.tool_name == "recon"
        assert action.confidence == 0.9
        assert action.risk_assessment == "low"
        assert action.done is False

    def test_parse_action_clamps_confidence(self) -> None:
        raw = {"tool_name": "recon", "parameters": {}, "reasoning": "", "confidence": 99.0, "risk_assessment": "low", "done": False}
        action = _parse_action(raw)
        assert action.confidence == 1.0

    def test_parse_action_invalid_risk_defaults_low(self) -> None:
        raw = {"tool_name": "recon", "parameters": {}, "reasoning": "", "confidence": 0.5, "risk_assessment": "extreme", "done": False}
        action = _parse_action(raw)
        assert action.risk_assessment == "low"

    def test_parse_action_done_inferred_from_tool_name(self) -> None:
        raw = {"tool_name": "done", "parameters": {"summary": "x"}, "reasoning": "", "confidence": 1.0, "risk_assessment": "low"}
        action = _parse_action(raw)
        assert action.done is True

    @pytest.mark.asyncio
    async def test_is_available_returns_false_when_ollama_unreachable(self) -> None:
        provider = OllamaProvider(base_url="http://localhost:19999")
        result = await provider.is_available()
        assert result is False

    def _make_http_mock(self, response_body: dict) -> Any:
        """Build an AsyncMock that works as an `async with httpx.AsyncClient()` context manager."""
        from unittest.mock import MagicMock

        response = MagicMock()
        response.json.return_value = response_body
        response.raise_for_status = MagicMock()

        client = AsyncMock()
        client.post = AsyncMock(return_value=response)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        return client

    @pytest.mark.asyncio
    async def test_plan_next_action_returns_parse_failure_on_bad_response(self) -> None:
        provider = OllamaProvider()
        ctx = _ctx()
        tools = get_all_tools()

        client_mock = self._make_http_mock({"message": {"content": "not json at all"}})
        with patch("httpx.AsyncClient", return_value=client_mock):
            action = await provider.plan_next_action(ctx, tools)

        assert action.done is True
        assert action.confidence == 0.0

    @pytest.mark.asyncio
    async def test_plan_next_action_returns_valid_action(self) -> None:
        provider = OllamaProvider()
        ctx = _ctx()
        tools = get_all_tools()

        expected_json = json.dumps({
            "tool_name": "recon",
            "parameters": {"target": "10.0.0.1"},
            "reasoning": "start with passive recon",
            "confidence": 0.9,
            "risk_assessment": "low",
            "done": False,
        })

        client_mock = self._make_http_mock({"message": {"content": expected_json}})
        with patch("httpx.AsyncClient", return_value=client_mock):
            action = await provider.plan_next_action(ctx, tools)

        assert action.tool_name == "recon"
        assert action.confidence == 0.9
        assert action.done is False


# --------------------------------------------------------------------------- #
#  TASK-030 — Tool schema registry                                             #
# --------------------------------------------------------------------------- #

class TestToolRegistry:
    def test_all_tools_returns_list(self) -> None:
        tools = get_all_tools()
        assert len(tools) >= 5  # recon, portscan, servicenum, vulnanalysis, done

    def test_builtin_stages_present(self) -> None:
        names = {t.name for t in get_all_tools()}
        assert {"recon", "portscan", "servicenum", "vulnanalysis", "done"} <= names

    def test_get_tool_returns_schema(self) -> None:
        ts = get_tool("recon")
        assert ts is not None
        assert ts.risk_level == "low"

    def test_get_tool_missing_returns_none(self) -> None:
        assert get_tool("nonexistent") is None

    def test_register_custom_tool(self) -> None:
        schema = ToolSchema(
            name="custom_tool_test",
            description="test",
            parameters={"type": "object"},
            risk_level="low",
        )
        register_tool(schema)
        assert get_tool("custom_tool_test") is not None


# --------------------------------------------------------------------------- #
#  TASK-032 — Agent context builder                                            #
# --------------------------------------------------------------------------- #

class TestAgentContextBuilder:
    def test_build_empty_session(self) -> None:
        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"], objective="recon")
        ctx = build_agent_context(sm, sid, objective="recon", current_target="10.0.0.1")
        assert ctx.session_id == sid
        assert ctx.scope == ["10.0.0.1"]
        assert ctx.objective == "recon"
        assert ctx.findings == []
        assert ctx.targets == []

    def test_build_with_findings(self) -> None:
        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        sm.upsert_target(sid, "10.0.0.1", ip="10.0.0.1")
        sm.persist_stage_findings(sid, "10.0.0.1", "portscan", [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
        ])
        ctx = build_agent_context(sm, sid, current_target="10.0.0.1")
        assert len(ctx.findings) >= 1
        assert ctx.targets[0]["input"] == "10.0.0.1"

    def test_token_budget_trims_findings(self) -> None:
        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        sm.upsert_target(sid, "10.0.0.1", ip="10.0.0.1")
        # Insert many findings
        many_ports = [{"port": p, "protocol": "tcp", "state": "open", "service": "http"} for p in range(200)]
        sm.persist_stage_findings(sid, "10.0.0.1", "portscan", many_ports)
        # Use a very small budget
        ctx = build_agent_context(sm, sid, token_budget=500)
        # Should have fewer findings than total
        assert len(ctx.findings) < 200


# --------------------------------------------------------------------------- #
#  TASK-033 — System prompt                                                    #
# --------------------------------------------------------------------------- #

class TestPrompts:
    def test_system_prompt_contains_rules(self) -> None:
        ctx = _ctx()
        prompt = build_system_prompt(ctx, get_all_tools())
        assert "scope" in prompt.lower()
        assert "json" in prompt.lower()
        assert "tool_name" in prompt

    def test_system_prompt_contains_tools(self) -> None:
        ctx = _ctx()
        prompt = build_system_prompt(ctx, get_all_tools())
        assert "recon" in prompt
        assert "portscan" in prompt

    def test_system_prompt_contains_scope(self) -> None:
        ctx = _ctx(scope=["192.168.1.0/24"])
        prompt = build_system_prompt(ctx, get_all_tools())
        assert "192.168.1.0/24" in prompt

    def test_user_message_contains_target(self) -> None:
        ctx = _ctx(current_target="10.10.10.5")
        msg = build_user_message(ctx)
        assert "10.10.10.5" in msg

    def test_user_message_shows_findings(self) -> None:
        findings = [{"severity": "high", "finding_type": "vulnerability", "title": "CVE-2021-41773"}]
        ctx = _ctx(findings=findings)
        msg = build_user_message(ctx)
        assert "CVE-2021-41773" in msg

    def test_user_message_shows_last_action(self) -> None:
        action = AgentAction("recon", {}, "started recon", 0.8, "low")
        ctx = _ctx(history=[action])
        msg = build_user_message(ctx)
        assert "recon" in msg


# --------------------------------------------------------------------------- #
#  TASK-031 — ReAct loop                                                       #
# --------------------------------------------------------------------------- #

class TestAgentLoop:
    def _make_loop(self, provider: LLMProvider) -> AgentLoop:
        from unittest.mock import MagicMock
        orchestrator = MagicMock()
        orchestrator.run = AsyncMock(return_value=[])
        sm = _sm()
        return AgentLoop(
            provider=provider,
            orchestrator=orchestrator,
            session_manager=sm,
            max_iterations=5,
        )

    @pytest.mark.asyncio
    async def test_loop_stops_on_done_action(self) -> None:
        """Agent signals done on first call → loop terminates after 1 iteration."""
        class DoneProvider:
            async def plan_next_action(self, context: AgentContext, tools: list[ToolSchema]) -> AgentAction:
                return AgentAction("done", {"summary": "done"}, "all done", 1.0, "low", done=True)
            async def is_available(self) -> bool:
                return True

        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        loop = self._make_loop(DoneProvider())
        history = await loop.run(sid, "10.0.0.1", objective="recon")
        assert len(history) == 1
        assert history[0].done is True

    @pytest.mark.asyncio
    async def test_loop_respects_max_iterations(self) -> None:
        """Provider never returns done → loop stops at max_iterations."""
        class InfiniteProvider:
            async def plan_next_action(self, context: AgentContext, tools: list[ToolSchema]) -> AgentAction:
                return AgentAction("recon", {"target": "10.0.0.1"}, "keep going", 0.8, "low", done=False)
            async def is_available(self) -> bool:
                return True

        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        loop = self._make_loop(InfiniteProvider())
        history = await loop.run(sid, "10.0.0.1", objective="recon")
        assert len(history) == 5  # max_iterations

    @pytest.mark.asyncio
    async def test_loop_skips_high_risk_actions(self) -> None:
        """High-risk action is not executed but recorded in history with BLOCKED reasoning."""
        call_count = 0

        class HighRiskThenDoneProvider:
            async def plan_next_action(self, context: AgentContext, tools: list[ToolSchema]) -> AgentAction:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return AgentAction("vulnanalysis", {}, "exploit!", 0.9, "critical", done=False)
                return AgentAction("done", {"summary": "done"}, "stopped", 1.0, "low", done=True)

            async def is_available(self) -> bool:
                return True

        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        loop = self._make_loop(HighRiskThenDoneProvider())
        history = await loop.run(sid, "10.0.0.1", objective="recon")
        blocked = [a for a in history if "BLOCKED" in a.reasoning]
        assert len(blocked) >= 1

    @pytest.mark.asyncio
    async def test_dry_run_does_not_call_orchestrator(self) -> None:
        """In dry_run=True, the orchestrator.run() must never be called."""
        from unittest.mock import MagicMock
        orchestrator = MagicMock()
        orchestrator.run = AsyncMock(return_value=[])

        class ReconThenDoneProvider:
            _calls = 0
            async def plan_next_action(self, context: AgentContext, tools: list[ToolSchema]) -> AgentAction:
                self.__class__._calls += 1
                if self.__class__._calls == 1:
                    return AgentAction("recon", {"target": "10.0.0.1"}, "recon first", 0.9, "low", done=False)
                return AgentAction("done", {"summary": "x"}, "done", 1.0, "low", done=True)

            async def is_available(self) -> bool:
                return True

        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        loop = AgentLoop(
            provider=ReconThenDoneProvider(),
            orchestrator=orchestrator,
            session_manager=sm,
            max_iterations=5,
        )
        await loop.run(sid, "10.0.0.1", dry_run=True)
        orchestrator.run.assert_not_called()
