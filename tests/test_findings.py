import pytest

from mylilpwny.persistence.db import create_db_engine, get_session_factory, init_db
from mylilpwny.persistence.session import SessionManager, stage_to_findings


# --- stage_to_findings conversion ---

def test_portscan_finding_title():
    findings = stage_to_findings("portscan", [{"port": 22, "protocol": "tcp", "state": "open"}])
    assert len(findings) == 1
    assert findings[0]["title"] == "Port 22/tcp open"
    assert findings[0]["finding_type"] == "open_port"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["evidence"]["port"] == 22


def test_portscan_empty():
    assert stage_to_findings("portscan", []) == []


def test_portscan_multiple_ports():
    raw = [{"port": 80, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}]
    findings = stage_to_findings("portscan", raw)
    assert len(findings) == 2
    assert findings[0]["title"] == "Port 80/tcp open"
    assert findings[1]["title"] == "Port 443/tcp open"


def test_servicenum_with_version():
    raw = [{"port": 22, "name": "ssh", "version": "OpenSSH 8.9"}]
    findings = stage_to_findings("servicenum", raw)
    assert findings[0]["finding_type"] == "service"
    assert findings[0]["severity"] == "info"
    assert "OpenSSH 8.9" in findings[0]["title"]


def test_servicenum_without_version():
    raw = [{"port": 80, "name": "http", "version": None}]
    findings = stage_to_findings("servicenum", raw)
    assert findings[0]["title"] == "Service http on port 80"


def test_recon_discovery_summary():
    raw = [{"hostnames": ["a.example.com", "b.example.com"], "ips": ["1.2.3.4"]}]
    findings = stage_to_findings("recon", raw)
    summary = next(f for f in findings if "host(s) discovered" in f["title"])
    assert "3" in summary["title"]  # 2 hostnames + 1 ip


def test_recon_individual_subdomain_findings():
    raw = [{"hostnames": ["www.example.com"], "ips": []}]
    findings = stage_to_findings("recon", raw)
    subdomain_titles = [f["title"] for f in findings if "Subdomain" in f["title"]]
    assert "Subdomain: www.example.com" in subdomain_titles


def test_recon_empty():
    assert stage_to_findings("recon", []) == []


def test_vulnanalysis_critical_cvss():
    raw = [{"cve_id": "CVE-2021-41773", "cvss": 9.8, "description": "Path traversal"}]
    findings = stage_to_findings("vulnanalysis", raw)
    assert findings[0]["finding_type"] == "vulnerability"
    assert findings[0]["severity"] == "critical"
    assert findings[0]["title"] == "CVE-2021-41773"


def test_vulnanalysis_high_cvss():
    raw = [{"cve_id": "CVE-2022-12345", "cvss": 7.5}]
    findings = stage_to_findings("vulnanalysis", raw)
    assert findings[0]["severity"] == "high"


def test_vulnanalysis_medium_cvss():
    raw = [{"cvss": 5.0, "title": "some-exploit"}]
    findings = stage_to_findings("vulnanalysis", raw)
    assert findings[0]["severity"] == "medium"
    assert findings[0]["title"] == "some-exploit"


def test_vulnanalysis_uses_severity_field_if_present():
    raw = [{"cve_id": "CVE-X", "severity": "High", "cvss": None}]
    findings = stage_to_findings("vulnanalysis", raw)
    assert findings[0]["severity"] == "high"


def test_unknown_stage_returns_empty():
    assert stage_to_findings("unknown_stage", [{"foo": "bar"}]) == []


# --- persist_stage_findings integration ---

@pytest.fixture
def sm():
    engine = create_db_engine(":memory:")
    init_db(engine)
    return SessionManager(get_session_factory(engine))


def test_persist_stage_findings_stores_rows(sm):
    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1")
    count = sm.persist_stage_findings(
        sid, "10.0.0.1", "portscan",
        [{"port": 22, "protocol": "tcp"}, {"port": 80, "protocol": "tcp"}],
    )
    assert count == 2
    findings = sm.get_findings(sid)
    assert len(findings) == 2


def test_persist_stage_findings_empty_does_nothing(sm):
    sid = sm.create_session()
    count = sm.persist_stage_findings(sid, "10.0.0.1", "portscan", [])
    assert count == 0
    assert sm.get_findings(sid) == []


def test_get_findings_filter_by_severity(sm):
    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1")
    sm.persist_stage_findings(sid, "10.0.0.1", "portscan", [{"port": 22, "protocol": "tcp"}])
    sm.persist_stage_findings(sid, "10.0.0.1", "vulnanalysis",
                              [{"cve_id": "CVE-1", "cvss": 9.9}])
    critical = sm.get_findings(sid, severity="critical")
    assert len(critical) == 1
    assert critical[0].finding_type == "vulnerability"


def test_get_findings_filter_by_type(sm):
    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1")
    sm.persist_stage_findings(sid, "10.0.0.1", "portscan", [{"port": 80, "protocol": "tcp"}])
    sm.persist_stage_findings(sid, "10.0.0.1", "servicenum",
                              [{"port": 80, "name": "http"}])
    ports = sm.get_findings(sid, finding_type="open_port")
    assert len(ports) == 1


# --- audit log via pipeline (integration) ---

def test_audit_log_stage_events_recorded(sm):
    """Pipeline emits stage_start + stage_complete into audit log."""
    from unittest.mock import AsyncMock, patch
    from mylilpwny.config import Config
    from mylilpwny.core.pipeline import Pipeline
    from mylilpwny.core.scope import ScopeValidator
    from mylilpwny.core.state import Target
    from mylilpwny.modules.base import ModuleResult
    import asyncio

    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1")
    cfg = Config()
    scope = ScopeValidator(["10.0.0.1"])
    pipeline = Pipeline(cfg, scope, session_manager=sm, session_id=sid)
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    ok = ModuleResult(status="success", raw_output="", parsed_findings=[], duration=0.1)
    with patch("mylilpwny.core.pipeline.ReconModule") as MockRecon:
        MockRecon.return_value.run = AsyncMock(return_value=ok)
        asyncio.run(pipeline.run(target, stages=["recon"], dry_run=False))

    entries = sm.get_audit_log(sid)
    event_types = [e.event_type for e in entries]
    assert "stage_start" in event_types
    assert "stage_complete" in event_types


def test_tool_run_logged_after_stage(sm):
    """Pipeline logs tool_run rows for each completed stage (dry_run mode)."""
    from mylilpwny.config import Config
    from mylilpwny.core.pipeline import Pipeline
    from mylilpwny.core.scope import ScopeValidator
    from mylilpwny.core.state import Target
    import asyncio

    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1")
    cfg = Config()
    scope = ScopeValidator(["10.0.0.1"])
    pipeline = Pipeline(cfg, scope, session_manager=sm, session_id=sid)
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    asyncio.run(pipeline.run(target, stages=["portscan"], dry_run=True))

    runs = sm.get_tool_runs(sid)
    assert len(runs) == 1
    assert runs[0].module == "portscan"
    assert runs[0].status == "skipped"
