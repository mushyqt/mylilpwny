from unittest.mock import patch

from mylilpwny.core.deps import ToolSpec, ToolStatus, check_all, missing_required


def _make_status(name: str, required: bool, installed: bool) -> ToolStatus:
    spec = ToolSpec(name=name, required=required, description="", install_hint="")
    return ToolStatus(spec=spec, path="/usr/bin/tool" if installed else None)


def test_tool_status_installed():
    s = _make_status("nmap", required=True, installed=True)
    assert s.installed is True

def test_tool_status_missing():
    s = _make_status("nmap", required=True, installed=False)
    assert s.installed is False

def test_missing_required_returns_only_required_missing():
    statuses = [
        _make_status("nmap", required=True, installed=False),
        _make_status("masscan", required=False, installed=False),
        _make_status("whatweb", required=True, installed=True),
    ]
    missing = missing_required(statuses)
    assert len(missing) == 1
    assert missing[0].spec.name == "nmap"

def test_missing_required_empty_when_all_installed():
    statuses = [
        _make_status("nmap", required=True, installed=True),
        _make_status("masscan", required=False, installed=False),
    ]
    assert missing_required(statuses) == []

def test_check_all_returns_all_tools():
    results = check_all()
    names = [s.spec.name for s in results]
    assert "nmap" in names
    assert "masscan" in names
    assert "searchsploit" in names

def test_check_all_nmap_installed():
    results = check_all()
    nmap = next(s for s in results if s.spec.name == "nmap")
    assert nmap.installed

def test_check_all_with_missing_tool():
    with patch("shutil.which", return_value=None):
        results = check_all()
        assert all(not s.installed for s in results)
