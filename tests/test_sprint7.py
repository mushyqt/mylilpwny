"""Sprint 7 tests: Memory, KnowledgeBase, RiskClassifier, ConfirmationGate (TASK-034–039)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mylilpwny.agent.context import build_agent_context
from mylilpwny.agent.gate import ConfirmationGate
from mylilpwny.agent.knowledge import KnowledgeBase
from mylilpwny.agent.loop import AgentLoop
from mylilpwny.agent.memory import AgentMemory
from mylilpwny.agent import risk as risk_mod
from mylilpwny.agent.types import AgentAction, AgentContext, ToolSchema
from mylilpwny.persistence.db import setup_database
from mylilpwny.persistence.session import SessionManager


# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _sm() -> SessionManager:
    _, factory = setup_database(":memory:")
    return SessionManager(factory)


def _action(tool: str, *, risk: str = "low", done: bool = False, **params: object) -> AgentAction:
    return AgentAction(
        tool_name=tool,
        parameters=dict(params),
        reasoning="test",
        confidence=0.9,
        risk_assessment=risk,  # type: ignore[arg-type]
        done=done,
    )


# --------------------------------------------------------------------------- #
#  TASK-034 — AgentMemory                                                      #
# --------------------------------------------------------------------------- #

class TestAgentMemory:
    def test_add_and_snapshot(self) -> None:
        m = AgentMemory()
        m.add("open port 22")
        m.add("service: ssh")
        snap = m.snapshot()
        assert "open port 22" in snap
        assert "service: ssh" in snap

    def test_snapshot_returns_copy(self) -> None:
        m = AgentMemory()
        m.add("note1")
        s1 = m.snapshot()
        m.add("note2")
        s2 = m.snapshot()
        assert len(s1) == 1
        assert len(s2) == 2

    def test_clear(self) -> None:
        m = AgentMemory()
        m.add("x")
        m.clear()
        assert m.snapshot() == []

    def test_max_notes_capped(self) -> None:
        m = AgentMemory(max_notes=3)
        for i in range(10):
            m.add(f"note {i}")
        assert len(m.snapshot()) <= 3

    @pytest.mark.asyncio
    async def test_loop_remember_tool_adds_note(self) -> None:
        """When agent calls 'remember', the note is stored in memory and shown next iteration."""
        calls = 0
        notes_seen: list[list[str]] = []

        class RememberProvider:
            async def plan_next_action(self, ctx: AgentContext, tools: list[ToolSchema]) -> AgentAction:
                nonlocal calls
                calls += 1
                notes_seen.append(list(ctx.memory_notes))
                if calls == 1:
                    return _action("remember", note="found SSH on port 22")
                return _action("done", done=True, summary="done")

            async def is_available(self) -> bool:
                return True

        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        orchestrator = MagicMock()
        orchestrator.run = AsyncMock(return_value=[])
        loop = AgentLoop(
            provider=RememberProvider(),
            orchestrator=orchestrator,
            session_manager=sm,
            dry_run=True,
            max_iterations=5,
        )
        history = await loop.run(sid, "10.0.0.1", objective="recon")
        assert calls == 2
        assert notes_seen[0] == []
        assert any("found SSH on port 22" in n for n in notes_seen[1])


# --------------------------------------------------------------------------- #
#  TASK-035 + TASK-036 — KnowledgeBase                                         #
# --------------------------------------------------------------------------- #

class TestKnowledgeBase:
    def test_seed_query_vsftpd(self) -> None:
        sm = _sm()
        kb = KnowledgeBase(sm)
        result = kb.query("vsftpd")
        assert "vsftpd" in result.lower()

    def test_seed_query_openssh(self) -> None:
        sm = _sm()
        kb = KnowledgeBase(sm)
        result = kb.query("openssh")
        assert "openssh" in result.lower() or "ssh" in result.lower()

    def test_no_match_returns_no_knowledge_message(self) -> None:
        sm = _sm()
        kb = KnowledgeBase(sm)
        result = kb.query("xyzzy_nonexistent_service_99")
        assert "No knowledge found" in result

    def test_db_findings_included_in_results(self) -> None:
        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        sm.upsert_target(sid, "10.0.0.1", ip="10.0.0.1")
        sm.add_finding(
            sid,
            target_input="10.0.0.1",
            finding_type="vulnerability",
            severity="high",
            title="EternalBlue MS17-010",
            description="SMB RCE",
            evidence={"port": 445},
        )
        kb = KnowledgeBase(sm)
        result = kb.query("EternalBlue")
        assert "EternalBlue" in result or "DB/" in result

    @pytest.mark.asyncio
    async def test_loop_query_memory_tool_injects_result(self) -> None:
        """When agent calls 'query_memory', the KB result is added to memory_notes."""
        calls = 0
        notes_after: list[list[str]] = []

        class QueryThenDoneProvider:
            async def plan_next_action(self, ctx: AgentContext, tools: list[ToolSchema]) -> AgentAction:
                nonlocal calls
                calls += 1
                notes_after.append(list(ctx.memory_notes))
                if calls == 1:
                    return _action("query_memory", query="vsftpd")
                return _action("done", done=True, summary="done")

            async def is_available(self) -> bool:
                return True

        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        orchestrator = MagicMock()
        orchestrator.run = AsyncMock(return_value=[])
        loop = AgentLoop(
            provider=QueryThenDoneProvider(),
            orchestrator=orchestrator,
            session_manager=sm,
            dry_run=True,
            max_iterations=5,
        )
        await loop.run(sid, "10.0.0.1", objective="recon")
        # On second call, memory_notes should contain the KB result
        assert calls == 2
        assert any("[KB]" in n for n in notes_after[1])


# --------------------------------------------------------------------------- #
#  TASK-037 — Risk Classifier                                                  #
# --------------------------------------------------------------------------- #

class TestRiskClassifier:
    def test_recon_always_low_regardless_of_llm(self) -> None:
        a = _action("recon", risk="critical")
        assert risk_mod.classify(a) == "low"

    def test_remember_always_low(self) -> None:
        assert risk_mod.classify(_action("remember", risk="high")) == "low"

    def test_query_memory_always_low(self) -> None:
        assert risk_mod.classify(_action("query_memory", risk="high")) == "low"

    def test_done_always_low(self) -> None:
        assert risk_mod.classify(_action("done", done=True, risk="medium")) == "low"

    def test_portscan_floor_is_medium(self) -> None:
        a = _action("portscan", risk="low")
        assert risk_mod.classify(a) == "medium"

    def test_portscan_llm_high_is_preserved(self) -> None:
        a = _action("portscan", risk="high")
        assert risk_mod.classify(a) == "high"

    def test_unknown_tool_trusts_llm(self) -> None:
        a = _action("exploit_rce", risk="critical")
        assert risk_mod.classify(a) == "critical"

    def test_exceeds_threshold(self) -> None:
        assert risk_mod.exceeds_threshold("high", "medium") is True
        assert risk_mod.exceeds_threshold("low", "medium") is False
        assert risk_mod.exceeds_threshold("medium", "medium") is True
        assert risk_mod.exceeds_threshold("critical", "high") is True


# --------------------------------------------------------------------------- #
#  TASK-038 — ConfirmationGate                                                 #
# --------------------------------------------------------------------------- #

class TestConfirmationGate:
    def test_dry_run_never_requires_confirmation(self) -> None:
        gate = ConfirmationGate(mode="manual", dry_run=True)
        a = _action("portscan", risk="critical")
        assert gate.requires_confirmation(a, "critical") is False

    def test_manual_mode_requires_confirmation_for_medium(self) -> None:
        gate = ConfirmationGate(mode="manual")
        a = _action("portscan", risk="medium")
        assert gate.requires_confirmation(a, "medium") is True

    def test_semi_auto_does_not_require_for_medium(self) -> None:
        gate = ConfirmationGate(mode="semi-auto")
        a = _action("portscan", risk="medium")
        assert gate.requires_confirmation(a, "medium") is False

    def test_semi_auto_requires_for_high(self) -> None:
        gate = ConfirmationGate(mode="semi-auto")
        a = _action("exploit", risk="high")
        assert gate.requires_confirmation(a, "high") is True

    def test_autonomous_requires_only_critical(self) -> None:
        gate = ConfirmationGate(mode="autonomous")
        assert gate.requires_confirmation(_action("x", risk="high"), "high") is False
        assert gate.requires_confirmation(_action("x", risk="critical"), "critical") is True

    def test_request_confirmation_y_returns_proceed(self) -> None:
        gate = ConfirmationGate(mode="manual")
        with patch("builtins.input", return_value="y"):
            decision = gate.request_confirmation(_action("portscan", risk="medium"), "medium")
        assert decision == "proceed"

    def test_request_confirmation_s_returns_skip(self) -> None:
        gate = ConfirmationGate(mode="manual")
        with patch("builtins.input", return_value="s"):
            decision = gate.request_confirmation(_action("portscan", risk="medium"), "medium")
        assert decision == "skip"

    def test_request_confirmation_a_returns_abort(self) -> None:
        gate = ConfirmationGate(mode="manual")
        with patch("builtins.input", return_value="a"):
            decision = gate.request_confirmation(_action("portscan", risk="medium"), "medium")
        assert decision == "abort"

    def test_request_confirmation_eof_returns_abort(self) -> None:
        gate = ConfirmationGate(mode="manual")
        with patch("builtins.input", side_effect=EOFError):
            decision = gate.request_confirmation(_action("portscan", risk="medium"), "medium")
        assert decision == "abort"

    @pytest.mark.asyncio
    async def test_gate_abort_stops_loop(self) -> None:
        """Gate returning 'abort' should stop the loop immediately."""
        calls = 0

        class HighRiskProvider:
            async def plan_next_action(self, ctx: AgentContext, tools: list[ToolSchema]) -> AgentAction:
                nonlocal calls
                calls += 1
                return _action("portscan", risk="medium")

            async def is_available(self) -> bool:
                return True

        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        orchestrator = MagicMock()
        orchestrator.run = AsyncMock(return_value=[])
        loop = AgentLoop(
            provider=HighRiskProvider(),
            orchestrator=orchestrator,
            session_manager=sm,
            max_iterations=10,
            mode="manual",
        )
        with patch("mylilpwny.agent.gate.ConfirmationGate.request_confirmation", return_value="abort"):
            history = await loop.run(sid, "10.0.0.1", objective="recon")

        assert calls == 1
        aborted = [a for a in history if "ABORTED" in a.reasoning]
        assert len(aborted) == 1


# --------------------------------------------------------------------------- #
#  TASK-039 — Completed stages tracking (regression)                           #
# --------------------------------------------------------------------------- #

class TestCompletedStagesTracking:
    def test_completed_stages_in_context(self) -> None:
        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        sm.upsert_target(sid, "10.0.0.1", ip="10.0.0.1")
        sm.audit(sid, event_type="stage_complete", target="10.0.0.1", module="recon")
        sm.audit(sid, event_type="stage_complete", target="10.0.0.1", module="portscan")

        ctx = build_agent_context(sm, sid, current_target="10.0.0.1")
        assert "recon" in ctx.completed_stages
        assert "portscan" in ctx.completed_stages
        assert "servicenum" not in ctx.completed_stages

    def test_completed_stages_not_duplicated(self) -> None:
        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        sm.upsert_target(sid, "10.0.0.1", ip="10.0.0.1")
        sm.audit(sid, event_type="stage_complete", target="10.0.0.1", module="recon")
        sm.audit(sid, event_type="stage_complete", target="10.0.0.1", module="recon")

        ctx = build_agent_context(sm, sid, current_target="10.0.0.1")
        assert ctx.completed_stages.count("recon") == 1

    def test_memory_notes_passed_to_context(self) -> None:
        sm = _sm()
        sid = sm.create_session(scope=["10.0.0.1"])
        ctx = build_agent_context(sm, sid, current_target="10.0.0.1", memory_notes=["note A", "note B"])
        assert "note A" in ctx.memory_notes
        assert "note B" in ctx.memory_notes
