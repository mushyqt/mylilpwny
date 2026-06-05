import pytest

from mylilpwny.core.state import Target, TargetState
from mylilpwny.modules.base import BaseModule, ModuleResult


class _EchoModule(BaseModule):
    name = "echo"
    description = "Test module"
    risk_level = "low"

    async def run(self, target: Target, options: dict) -> ModuleResult:
        return ModuleResult(
            status="success",
            raw_output=f"echo {target.input}",
            parsed_findings=[{"target": target.input}],
            duration=0.1,
            command_run=f"echo {target.input}",
        )


class _MissingDepsModule(BaseModule):
    name = "nodeps"
    description = "Module with missing deps"
    risk_level = "medium"

    async def run(self, target: Target, options: dict) -> ModuleResult:
        return ModuleResult(status="skipped", raw_output="", parsed_findings=[], duration=0.0)

    def check_dependencies(self) -> list[str]:
        return ["nonexistent-tool-xyz"]


# --- Target ---

def test_target_defaults():
    t = Target(input="10.0.0.1")
    assert t.state == TargetState.DISCOVERED
    assert t.ip is None

def test_target_to_dict():
    t = Target(input="10.0.0.1", ip="10.0.0.1", state=TargetState.SCANNED)
    d = t.to_dict()
    assert d["input"] == "10.0.0.1"
    assert d["state"] == "scanned"

def test_target_state_transition_valid():
    assert TargetState.DISCOVERED.can_transition_to(TargetState.SCANNED)

def test_target_state_transition_invalid():
    assert not TargetState.DISCOVERED.can_transition_to(TargetState.EXPLOITED)


# --- ModuleResult ---

def test_module_result_to_dict():
    r = ModuleResult(
        status="success",
        raw_output="output",
        parsed_findings=[{"port": 80}],
        duration=1.5,
        command_run="nmap -p 80 10.0.0.1",
    )
    d = r.to_dict()
    assert d["status"] == "success"
    assert d["duration"] == 1.5
    assert d["error"] is None


# --- BaseModule ---

@pytest.mark.asyncio
async def test_module_run():
    mod = _EchoModule()
    result = await mod.run(Target(input="10.0.0.1"), {})
    assert result.status == "success"
    assert result.parsed_findings[0]["target"] == "10.0.0.1"

def test_module_validate_options_default():
    assert _EchoModule().validate_options({}) is True

def test_module_check_dependencies_default():
    assert _EchoModule().check_dependencies() == []

def test_module_missing_deps():
    assert "nonexistent-tool-xyz" in _MissingDepsModule().check_dependencies()

def test_tool_available_known():
    assert _EchoModule()._tool_available("python3") is True

def test_tool_available_unknown():
    assert _EchoModule()._tool_available("nonexistent-tool-xyz") is False

def test_cannot_instantiate_base():
    with pytest.raises(TypeError):
        BaseModule()  # type: ignore[abstract]
