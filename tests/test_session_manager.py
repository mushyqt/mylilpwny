import pytest

from mylilpwny.persistence.db import create_db_engine, init_db, get_session_factory
from mylilpwny.persistence.session import SessionManager


@pytest.fixture
def sm():
    engine = create_db_engine(":memory:")
    init_db(engine)
    factory = get_session_factory(engine)
    return SessionManager(factory)


# --- create / get session ---

def test_create_session_returns_uuid(sm):
    sid = sm.create_session(scope=["10.0.0.0/24"])
    assert len(sid) == 36
    assert "-" in sid


def test_get_session_found(sm):
    sid = sm.create_session()
    sess = sm.get_session(sid)
    assert sess is not None
    assert sess.id == sid
    assert sess.status == "running"


def test_get_session_not_found(sm):
    assert sm.get_session("00000000-0000-0000-0000-000000000000") is None


def test_update_status(sm):
    sid = sm.create_session()
    sm.update_status(sid, "complete")
    sess = sm.get_session(sid)
    assert sess is not None
    assert sess.status == "complete"


def test_list_sessions(sm):
    for _ in range(3):
        sm.create_session()
    rows = sm.list_sessions()
    assert len(rows) >= 3


def test_list_sessions_respects_limit(sm):
    for _ in range(5):
        sm.create_session()
    rows = sm.list_sessions(limit=2)
    assert len(rows) == 2


# --- upsert target ---

def test_upsert_target_creates(sm):
    sid = sm.create_session()
    tid = sm.upsert_target(sid, "10.0.0.1", ip="10.0.0.1", state="discovered")
    assert len(tid) == 36


def test_upsert_target_updates(sm):
    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1", ip="10.0.0.1", state="discovered")
    sm.upsert_target(sid, "10.0.0.1", state="scanned")
    targets = sm.get_targets(sid)
    assert len(targets) == 1
    assert targets[0].state == "scanned"


def test_get_targets(sm):
    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1")
    sm.upsert_target(sid, "10.0.0.2")
    targets = sm.get_targets(sid)
    inputs = {t.input for t in targets}
    assert inputs == {"10.0.0.1", "10.0.0.2"}


# --- findings ---

def test_add_finding(sm):
    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1")
    fid = sm.add_finding(
        sid,
        target_input="10.0.0.1",
        finding_type="open_port",
        severity="medium",
        title="Port 22/tcp open",
        evidence={"port": 22},
    )
    assert len(fid) == 36


def test_add_finding_without_target(sm):
    sid = sm.create_session()
    fid = sm.add_finding(sid, finding_type="info", title="Generic finding")
    assert len(fid) == 36


# --- tool runs ---

def test_log_tool_run(sm):
    sid = sm.create_session()
    rid = sm.log_tool_run(sid, target="10.0.0.1", module="portscan",
                          command="nmap -p- 10.0.0.1", exit_code=0, duration=5.2)
    assert len(rid) == 36


def test_get_tool_runs(sm):
    sid = sm.create_session()
    sm.log_tool_run(sid, target="10.0.0.1", module="recon")
    sm.log_tool_run(sid, target="10.0.0.1", module="portscan")
    runs = sm.get_tool_runs(sid)
    assert len(runs) == 2
    assert runs[0].module == "recon"
    assert runs[1].module == "portscan"


# --- audit log ---

def test_audit(sm):
    sid = sm.create_session()
    sm.audit(sid, "stage_start", target="10.0.0.1", module="recon", detail={"dry_run": False})
    entries = sm.get_audit_log(sid)
    assert len(entries) == 1
    assert entries[0].event_type == "stage_start"
    assert entries[0].detail == {"dry_run": False}


def test_audit_log_ordered_by_time(sm):
    sid = sm.create_session()
    for event in ("stage_start", "stage_complete", "target_complete"):
        sm.audit(sid, event)
    entries = sm.get_audit_log(sid)
    event_types = [e.event_type for e in entries]
    assert event_types == ["stage_start", "stage_complete", "target_complete"]
