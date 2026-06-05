import json
from datetime import datetime, timezone

import pytest

from mylilpwny.persistence.db import create_db_engine, get_session_factory, init_db
from mylilpwny.persistence.session import SessionManager
from mylilpwny.reporting.report import (
    ReportData,
    build_report_data,
    console_summary,
    to_json,
    to_markdown,
)


# --- fixtures ---

@pytest.fixture
def sm():
    engine = create_db_engine(":memory:")
    init_db(engine)
    return SessionManager(get_session_factory(engine))


@pytest.fixture
def populated_session(sm):
    """A session with one target, one finding, one tool run."""
    sid = sm.create_session(scope=["10.0.0.0/24"], objective="vuln-scan")
    sm.upsert_target(sid, "10.0.0.1", ip="10.0.0.1", state="analyzed")
    sm.persist_stage_findings(sid, "10.0.0.1", "portscan",
                              [{"port": 22, "protocol": "tcp"},
                               {"port": 80, "protocol": "tcp"}])
    sm.persist_stage_findings(sid, "10.0.0.1", "vulnanalysis",
                              [{"cve_id": "CVE-2021-41773", "cvss": 9.8,
                                "description": "Path traversal in Apache"}])
    sm.log_tool_run(sid, target="10.0.0.1", module="portscan",
                    command="nmap -p- 10.0.0.1", exit_code=0, duration=5.2)
    return sid


# --- build_report_data ---

def test_build_report_data_session_not_found(sm):
    with pytest.raises(ValueError, match="not found"):
        build_report_data(sm, "00000000-0000-0000-0000-000000000000")


def test_build_report_data_returns_report_data(sm, populated_session):
    data = build_report_data(sm, populated_session)
    assert isinstance(data, ReportData)
    assert data.session_id == populated_session
    assert data.status == "running"
    assert data.objective == "vuln-scan"
    assert "10.0.0.0/24" in data.scope


def test_build_report_data_targets(sm, populated_session):
    data = build_report_data(sm, populated_session)
    assert len(data.targets) == 1
    assert data.targets[0]["input"] == "10.0.0.1"
    assert data.targets[0]["state"] == "analyzed"


def test_build_report_data_findings_sorted_by_severity(sm, populated_session):
    data = build_report_data(sm, populated_session)
    # vulnerability (critical CVSS 9.8) should come before open_port (medium)
    assert data.findings[0]["severity"] == "critical"


def test_build_report_data_tool_runs(sm, populated_session):
    data = build_report_data(sm, populated_session)
    assert len(data.tool_runs) == 1
    assert data.tool_runs[0]["module"] == "portscan"
    assert data.tool_runs[0]["duration"] == pytest.approx(5.2, abs=0.01)


# --- stats ---

def test_stats_counts_correctly(sm, populated_session):
    data = build_report_data(sm, populated_session)
    s = data.stats
    assert s["targets"] == 1
    assert s["open_ports"] == 2
    assert s["critical"] == 1
    assert s["medium"] == 2


def test_stats_empty_session(sm):
    sid = sm.create_session()
    data = build_report_data(sm, sid)
    s = data.stats
    assert s["targets"] == 0
    assert s["open_ports"] == 0
    assert s["critical"] == 0


# --- to_json ---

def test_to_json_is_valid_json(sm, populated_session):
    data = build_report_data(sm, populated_session)
    output = to_json(data)
    parsed = json.loads(output)
    assert parsed["session_id"] == populated_session
    assert "targets" in parsed
    assert "findings" in parsed
    assert "tool_runs" in parsed
    assert "stats" in parsed


def test_to_json_stats_embedded(sm, populated_session):
    data = build_report_data(sm, populated_session)
    parsed = json.loads(to_json(data))
    assert parsed["stats"]["open_ports"] == 2
    assert parsed["stats"]["critical"] == 1


def test_to_json_findings_sorted_by_severity(sm, populated_session):
    data = build_report_data(sm, populated_session)
    parsed = json.loads(to_json(data))
    if len(parsed["findings"]) > 1:
        from mylilpwny.reporting.report import _SEVERITY_ORDER
        sevs = [f["severity"] for f in parsed["findings"]]
        orders = [_SEVERITY_ORDER.get(s, 99) for s in sevs]
        assert orders == sorted(orders)


# --- to_markdown ---

def test_to_markdown_contains_session_id(sm, populated_session):
    data = build_report_data(sm, populated_session)
    md = to_markdown(data)
    assert populated_session in md


def test_to_markdown_has_executive_summary(sm, populated_session):
    data = build_report_data(sm, populated_session)
    md = to_markdown(data)
    assert "Executive Summary" in md
    assert "Targets scanned" in md


def test_to_markdown_has_findings_section(sm, populated_session):
    data = build_report_data(sm, populated_session)
    md = to_markdown(data)
    assert "Findings by Severity" in md
    assert "CVE-2021-41773" in md


def test_to_markdown_has_tool_run_timeline(sm, populated_session):
    data = build_report_data(sm, populated_session)
    md = to_markdown(data)
    assert "Tool Run Timeline" in md
    assert "portscan" in md


def test_to_markdown_empty_session(sm):
    sid = sm.create_session()
    data = build_report_data(sm, sid)
    md = to_markdown(data)
    assert "Executive Summary" in md


# --- console_summary ---

def test_console_summary_shows_counts(sm, populated_session):
    data = build_report_data(sm, populated_session)
    summary = console_summary(data)
    assert "Targets" in summary
    assert "Ports" in summary
    assert "2 open" in summary


def test_console_summary_shows_critical(sm, populated_session):
    data = build_report_data(sm, populated_session)
    summary = console_summary(data)
    assert "critical" in summary


def test_console_summary_no_vulns(sm):
    sid = sm.create_session()
    sm.upsert_target(sid, "10.0.0.1")
    data = build_report_data(sm, sid)
    summary = console_summary(data)
    assert "none" in summary
