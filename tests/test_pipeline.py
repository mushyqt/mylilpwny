from unittest.mock import AsyncMock, patch

import pytest

from mylilpwny.config import Config
from mylilpwny.core.pipeline import Pipeline, StageResult, _apply_findings, _build_options, STAGE_ORDER
from mylilpwny.core.scope import ScopeValidator
from mylilpwny.core.state import Target, TargetState
from mylilpwny.modules.base import ModuleResult


def _cfg() -> Config:
    return Config()


def _scope(target: str = "10.0.0.1") -> ScopeValidator:
    return ScopeValidator.from_target(target)


def _ok_result(findings: list = []) -> ModuleResult:
    return ModuleResult(status="success", raw_output="", parsed_findings=findings, duration=0.1)


# --- StageResult ---

def test_stage_result_success():
    r = StageResult(stage="recon", module_result=_ok_result())
    assert r.success is True

def test_stage_result_skipped_not_success():
    r = StageResult(stage="recon", skipped=True)
    assert r.success is False

def test_stage_result_error_not_success():
    r = StageResult(stage="recon", error="boom")
    assert r.success is False


# --- _build_options ---

def test_build_options_portscan_passes_timeout():
    target = Target(input="10.0.0.1")
    opts = _build_options("portscan", target, _cfg(), {})
    assert "timeout" in opts
    assert opts["timeout"] == 300

def test_build_options_servicenum_uses_target_ports():
    target = Target(input="10.0.0.1", ports=[{"port": 80}, {"port": 443}])
    opts = _build_options("servicenum", target, _cfg(), {})
    assert "80" in opts["ports"]
    assert "443" in opts["ports"]

def test_build_options_servicenum_no_ports_defaults():
    target = Target(input="10.0.0.1", ports=[])
    opts = _build_options("servicenum", target, _cfg(), {})
    assert opts["ports"] == "1-65535"

def test_build_options_vulnanalysis_passes_services():
    target = Target(input="10.0.0.1", services=[{"name": "http", "version": "Apache 2.4.52"}])
    opts = _build_options("vulnanalysis", target, _cfg(), {})
    assert opts["services"][0]["name"] == "http"


# --- _apply_findings ---

def test_apply_findings_portscan():
    target = Target(input="10.0.0.1")
    result = _ok_result([{"port": 80, "protocol": "tcp", "state": "open"}])
    _apply_findings("portscan", target, result)
    assert target.ports[0]["port"] == 80

def test_apply_findings_servicenum():
    target = Target(input="10.0.0.1")
    result = _ok_result([{"port": 80, "name": "http", "version": "nginx"}])
    _apply_findings("servicenum", target, result)
    assert target.services[0]["name"] == "http"

def test_apply_findings_vulnanalysis():
    target = Target(input="10.0.0.1")
    result = _ok_result([{"cve": "CVE-2021-41773", "cvss": 7.5}])
    _apply_findings("vulnanalysis", target, result)
    assert target.vulnerabilities[0]["cve"] == "CVE-2021-41773"


# --- Pipeline.run() ---

@pytest.mark.asyncio
async def test_pipeline_dry_run_skips_all_modules():
    pipeline = Pipeline(_cfg(), _scope())
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    results = await pipeline.run(target, dry_run=True)

    assert len(results) == len(STAGE_ORDER)
    for r in results:
        assert r.module_result is not None
        assert r.module_result.status == "skipped"


@pytest.mark.asyncio
async def test_pipeline_out_of_scope_aborts():
    scope = ScopeValidator(["192.168.0.0/24"])
    pipeline = Pipeline(_cfg(), scope)
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    results = await pipeline.run(target)

    assert len(results) == 1
    assert "out of scope" in (results[0].error or "").lower()


@pytest.mark.asyncio
async def test_pipeline_skip_stage():
    pipeline = Pipeline(_cfg(), _scope())
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    results = await pipeline.run(target, dry_run=True, skip=["recon", "vulnanalysis"])

    skipped = {r.stage for r in results if r.skipped}
    assert "recon" in skipped
    assert "vulnanalysis" in skipped


@pytest.mark.asyncio
async def test_pipeline_single_stage():
    pipeline = Pipeline(_cfg(), _scope())
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    results = await pipeline.run(target, stages=["portscan"], dry_run=True)

    assert len(results) == 1
    assert results[0].stage == "portscan"


@pytest.mark.asyncio
async def test_pipeline_advances_target_state():
    pipeline = Pipeline(_cfg(), _scope())
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    mock_result = _ok_result([{"port": 80, "protocol": "tcp", "state": "open"}])

    with patch("mylilpwny.core.pipeline._run_stage_with_timeout", new_callable=AsyncMock,
               return_value=mock_result):
        await pipeline.run(target, stages=["portscan"])

    assert target.state == TargetState.SCANNED
    assert target.ports[0]["port"] == 80


@pytest.mark.asyncio
async def test_pipeline_continues_after_stage_error():
    pipeline = Pipeline(_cfg(), _scope())
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    call_count = 0

    async def mock_stage(module, target, options, timeout, dry_run):
        nonlocal call_count
        call_count += 1
        if module.name == "portscan":
            raise Exception("portscan failed")
        return _ok_result()

    with patch("mylilpwny.core.pipeline._run_stage_with_timeout", side_effect=mock_stage):
        results = await pipeline.run(target, stages=["recon", "portscan", "servicenum"])

    assert call_count == 3
    errors = [r for r in results if r.error]
    assert len(errors) == 1
    assert errors[0].stage == "portscan"


@pytest.mark.asyncio
async def test_pipeline_unknown_stage_skipped():
    pipeline = Pipeline(_cfg(), _scope())
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    results = await pipeline.run(target, stages=["nonexistent"], dry_run=True)

    assert results[0].skipped is True
