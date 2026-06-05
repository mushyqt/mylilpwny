import json

import pytest

from mylilpwny.core.state import InvalidStateTransitionError, Target, TargetState


# --- TargetState transitions ---

def test_valid_transitions():
    assert TargetState.DISCOVERED.can_transition_to(TargetState.SCANNED)
    assert TargetState.SCANNED.can_transition_to(TargetState.ENUMERATED)
    assert TargetState.ENUMERATED.can_transition_to(TargetState.ANALYZED)
    assert TargetState.ANALYZED.can_transition_to(TargetState.EXPLOITED)

def test_invalid_skip_transition():
    assert not TargetState.DISCOVERED.can_transition_to(TargetState.ENUMERATED)
    assert not TargetState.DISCOVERED.can_transition_to(TargetState.EXPLOITED)

def test_invalid_backward_transition():
    assert not TargetState.SCANNED.can_transition_to(TargetState.DISCOVERED)

def test_invalid_same_state():
    assert not TargetState.SCANNED.can_transition_to(TargetState.SCANNED)


# --- Target.transition() ---

def test_transition_advances_state():
    t = Target(input="10.0.0.1")
    t.transition(TargetState.SCANNED)
    assert t.state == TargetState.SCANNED

def test_transition_chained():
    t = Target(input="10.0.0.1")
    t.transition(TargetState.SCANNED)
    t.transition(TargetState.ENUMERATED)
    t.transition(TargetState.ANALYZED)
    assert t.state == TargetState.ANALYZED

def test_transition_invalid_raises():
    t = Target(input="10.0.0.1")
    with pytest.raises(InvalidStateTransitionError):
        t.transition(TargetState.EXPLOITED)

def test_transition_backward_raises():
    t = Target(input="10.0.0.1", state=TargetState.ANALYZED)
    with pytest.raises(InvalidStateTransitionError):
        t.transition(TargetState.SCANNED)


# --- Target serialisation ---

def test_to_dict_minimal():
    t = Target(input="10.0.0.1")
    d = t.to_dict()
    assert d["input"] == "10.0.0.1"
    assert d["state"] == "discovered"
    assert d["ports"] == []
    assert d["vulnerabilities"] == []

def test_to_dict_with_plain_dicts():
    t = Target(
        input="10.0.0.1",
        ip="10.0.0.1",
        ports=[{"port": 80, "protocol": "tcp", "state": "open"}],
        state=TargetState.SCANNED,
    )
    d = t.to_dict()
    assert d["ports"][0]["port"] == 80
    assert d["state"] == "scanned"

def test_to_dict_calls_to_dict_on_items():
    class FakePort:
        def to_dict(self) -> dict:
            return {"port": 443, "protocol": "tcp", "state": "open"}

    t = Target(input="10.0.0.1", ports=[FakePort()])
    d = t.to_dict()
    assert d["ports"][0]["port"] == 443

def test_to_json_is_valid_json():
    t = Target(input="10.0.0.1", ip="10.0.0.1")
    raw = t.to_json()
    parsed = json.loads(raw)
    assert parsed["input"] == "10.0.0.1"


# --- Target.from_dict() ---

def test_from_dict_roundtrip():
    t = Target(input="example.com", ip="1.2.3.4", hostname="example.com",
               state=TargetState.ANALYZED, metadata={"note": "test"})
    restored = Target.from_dict(t.to_dict())
    assert restored.input == t.input
    assert restored.ip == t.ip
    assert restored.state == t.state
    assert restored.metadata == t.metadata

def test_from_dict_defaults():
    t = Target.from_dict({"input": "10.0.0.1"})
    assert t.state == TargetState.DISCOVERED
    assert t.ports == []
