import pytest
from sqlalchemy import inspect, text

from mylilpwny.persistence.db import create_db_engine, init_db, setup_database, get_session_factory
from mylilpwny.persistence.models import AuditEntry, Finding, Session, TargetRecord, ToolRun


# --- helpers ---

@pytest.fixture
def engine():
    e = create_db_engine(":memory:")
    init_db(e)
    return e

@pytest.fixture
def db(engine):
    return get_session_factory(engine)


# --- schema ---

def test_all_tables_created(engine):
    table_names = inspect(engine).get_table_names()
    assert "sessions" in table_names
    assert "targets" in table_names
    assert "findings" in table_names
    assert "tool_runs" in table_names
    assert "audit_log" in table_names


def test_init_db_is_idempotent(engine):
    init_db(engine)  # second call must not raise
    table_names = inspect(engine).get_table_names()
    assert len([t for t in table_names if t in
                {"sessions", "targets", "findings", "tool_runs", "audit_log"}]) == 5


# --- CRUD ---

def test_create_session(db):
    with db() as s:
        sess = Session(scope=["10.0.0.0/24"], objective="vuln-scan")
        s.add(sess)
        s.commit()
        assert sess.id is not None
        assert sess.status == "running"


def test_create_target_linked_to_session(db):
    with db() as s:
        sess = Session()
        s.add(sess)
        s.flush()
        target = TargetRecord(session_id=sess.id, input="10.0.0.1", ip="10.0.0.1")
        s.add(target)
        s.commit()
        assert target.id is not None
        assert target.session_id == sess.id


def test_create_finding(db):
    with db() as s:
        sess = Session()
        s.add(sess)
        s.flush()
        finding = Finding(
            session_id=sess.id,
            finding_type="open_port",
            severity="medium",
            title="Port 22/tcp open",
            evidence={"port": 22, "protocol": "tcp"},
        )
        s.add(finding)
        s.commit()
        assert finding.id is not None
        assert finding.severity == "medium"


def test_create_tool_run(db):
    with db() as s:
        sess = Session()
        s.add(sess)
        s.flush()
        run = ToolRun(
            session_id=sess.id,
            target="10.0.0.1",
            module="portscan",
            command="nmap -p- 10.0.0.1",
            exit_code=0,
            duration=12.3,
        )
        s.add(run)
        s.commit()
        assert run.id is not None
        assert run.duration == 12.3


def test_create_audit_entry(db):
    with db() as s:
        sess = Session()
        s.add(sess)
        s.flush()
        entry = AuditEntry(
            session_id=sess.id,
            event_type="stage_start",
            target="10.0.0.1",
            module="recon",
            detail={"dry_run": False},
        )
        s.add(entry)
        s.commit()
        assert entry.id is not None
        assert entry.event_type == "stage_start"


def test_session_cascade_deletes_targets(db):
    with db() as s:
        sess = Session()
        s.add(sess)
        s.flush()
        t = TargetRecord(session_id=sess.id, input="10.0.0.1")
        s.add(t)
        s.commit()
        sid = sess.id

        s.delete(sess)
        s.commit()
        remaining = s.query(TargetRecord).filter_by(session_id=sid).all()
        assert remaining == []


def test_setup_database_in_memory():
    engine, factory = setup_database(":memory:")
    table_names = inspect(engine).get_table_names()
    assert "sessions" in table_names
    with factory() as s:
        sess = Session(status="complete")
        s.add(sess)
        s.commit()
        assert sess.id is not None


def test_db_url_env_override(monkeypatch, tmp_path):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    from mylilpwny.persistence.db import _db_url
    assert str(db_file) in _db_url()
