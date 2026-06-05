from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mylilpwny.config import Config
from mylilpwny.core.orchestrator import Orchestrator, RunResult, expand_target, _is_ip
from mylilpwny.core.pipeline import StageResult
from mylilpwny.core.scope import ScopeValidator
from mylilpwny.core.state import Target
from mylilpwny.modules.base import ModuleResult


# --- expand_target ---

def test_expand_single_ip():
    assert expand_target("10.0.0.1") == ["10.0.0.1"]

def test_expand_cidr_24():
    hosts = expand_target("10.0.0.0/30")
    assert "10.0.0.1" in hosts
    assert "10.0.0.2" in hosts
    assert "10.0.0.0" not in hosts   # network address excluded
    assert "10.0.0.3" not in hosts   # broadcast excluded

def test_expand_cidr_32():
    assert expand_target("10.0.0.1/32") == ["10.0.0.1"]

def test_expand_hostname():
    assert expand_target("example.com") == ["example.com"]

def test_expand_comma_list():
    result = expand_target("10.0.0.1,10.0.0.2,example.com")
    assert result == ["10.0.0.1", "10.0.0.2", "example.com"]

def test_expand_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("10.0.0.1\n# comment\n10.0.0.2\n")
    result = expand_target(f"@{f}")
    assert result == ["10.0.0.1", "10.0.0.2"]

def test_expand_file_with_cidr(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("10.0.0.0/30\n")
    result = expand_target(f"@{f}")
    assert "10.0.0.1" in result
    assert "10.0.0.2" in result


# --- _is_ip ---

def test_is_ip_true():
    assert _is_ip("192.168.1.1") is True

def test_is_ip_false_hostname():
    assert _is_ip("example.com") is False

def test_is_ip_false_cidr():
    assert _is_ip("10.0.0.0/24") is False


# --- RunResult ---

def test_run_result_success():
    t = Target(input="10.0.0.1")
    ok = StageResult(stage="portscan", module_result=ModuleResult(
        status="success", raw_output="", parsed_findings=[], duration=0.1))
    r = RunResult(target=t, stage_results=[ok])
    assert r.success is True

def test_run_result_error():
    t = Target(input="10.0.0.1")
    r = RunResult(target=t, error="connection refused")
    assert r.success is False


# --- Orchestrator ---

def _cfg() -> Config:
    return Config()

def _scope() -> ScopeValidator:
    return ScopeValidator(["10.0.0.0/24"])


@pytest.mark.asyncio
async def test_orchestrator_single_target():
    orch = Orchestrator(_cfg(), _scope())

    ok_stages = [StageResult(stage="portscan", module_result=ModuleResult(
        status="success", raw_output="", parsed_findings=[], duration=0.1))]

    with patch("mylilpwny.core.orchestrator.Pipeline") as mock_pipeline_cls:
        mock_pipeline = mock_pipeline_cls.return_value
        mock_pipeline.run = AsyncMock(return_value=ok_stages)
        results = await orch.run("10.0.0.1", dry_run=True)

    assert len(results) == 1
    assert results[0].success is True


@pytest.mark.asyncio
async def test_orchestrator_cidr_expands():
    orch = Orchestrator(_cfg(), _scope())

    with patch("mylilpwny.core.orchestrator.Pipeline") as mock_pipeline_cls:
        mock_pipeline = mock_pipeline_cls.return_value
        mock_pipeline.run = AsyncMock(return_value=[
            StageResult(stage="portscan", module_result=ModuleResult(
                status="success", raw_output="", parsed_findings=[], duration=0.1))
        ])
        results = await orch.run("10.0.0.0/30", dry_run=True)

    # /30 has 2 usable hosts
    assert len(results) == 2


@pytest.mark.asyncio
async def test_orchestrator_respects_max_concurrent():
    cfg = Config()
    cfg.rate_limit.max_concurrent_targets = 1
    orch = Orchestrator(cfg, _scope())

    call_order: list[str] = []

    async def fake_run(target, **_):
        call_order.append(target.input)
        return []

    with patch("mylilpwny.core.orchestrator.Pipeline") as mock_pipeline_cls:
        mock_pipeline_cls.return_value.run = fake_run
        await orch.run("10.0.0.1,10.0.0.2", dry_run=True)

    assert len(call_order) == 2


@pytest.mark.asyncio
async def test_orchestrator_handles_target_exception():
    orch = Orchestrator(_cfg(), _scope())

    with patch("mylilpwny.core.orchestrator.Pipeline") as mock_pipeline_cls:
        mock_pipeline_cls.return_value.run = AsyncMock(side_effect=Exception("boom"))
        results = await orch.run("10.0.0.1", dry_run=True)

    assert results[0].error == "boom"
    assert results[0].success is False
