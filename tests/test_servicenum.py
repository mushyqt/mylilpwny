from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mylilpwny.core.state import Target
from mylilpwny.modules.servicenum import (
    Service,
    ServiceEnumModule,
    _merge_nse,
    _parse_nmap_services,
    _select_scripts,
)

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
        <script id="ssh-hostkey" output="2048 ab:cd:ef (RSA)"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.52"/>
        <script id="http-title" output="Apache2 Default Page"/>
        <script id="http-server-header" output="Apache/2.4.52 (Ubuntu)"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name="unknown"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


# --- Service ---

def test_service_to_dict():
    s = Service(port=80, protocol="tcp", name="http", version="Apache 2.4.52")
    d = s.to_dict()
    assert d["port"] == 80
    assert d["version"] == "Apache 2.4.52"
    assert d["banner"] is None
    assert d["nse_output"] == {}


# --- Parser ---

def test_parse_nmap_services_count():
    services = _parse_nmap_services(NMAP_XML)
    assert len(services) == 3  # closed port excluded

def test_parse_nmap_services_ssh():
    services = _parse_nmap_services(NMAP_XML)
    ssh = next(s for s in services if s.port == 22)
    assert ssh.name == "ssh"
    assert "OpenSSH" in (ssh.version or "")
    assert "ssh-hostkey" in ssh.nse_output

def test_parse_nmap_services_http():
    services = _parse_nmap_services(NMAP_XML)
    http = next(s for s in services if s.port == 80)
    assert http.name == "http"
    assert "Apache" in (http.version or "")
    assert "http-title" in http.nse_output
    assert "Apache2" in http.nse_output["http-title"]

def test_parse_nmap_services_empty():
    assert _parse_nmap_services("<nmaprun></nmaprun>") == []

def test_parse_nmap_services_invalid():
    assert _parse_nmap_services("bad xml") == []


# --- Script selection ---

def test_select_scripts_http():
    svcs = [Service(port=80, protocol="tcp", name="http")]
    scripts = _select_scripts(svcs)
    assert "http-title" in scripts
    assert "http-methods" in scripts

def test_select_scripts_smb():
    svcs = [Service(port=445, protocol="tcp", name="microsoft-ds")]
    scripts = _select_scripts(svcs)
    assert "smb-vuln-ms17-010" in scripts

def test_select_scripts_unknown_service():
    svcs = [Service(port=9999, protocol="tcp", name="unknown")]
    assert _select_scripts(svcs) == []

def test_select_scripts_deduplicates():
    svcs = [
        Service(port=80, protocol="tcp", name="http"),
        Service(port=8080, protocol="tcp", name="http"),
    ]
    scripts = _select_scripts(svcs)
    assert len(scripts) == len(set(scripts))


# --- NSE merge ---

def test_merge_nse_adds_scripts():
    base = [Service(port=80, protocol="tcp", name="http", nse_output={"http-title": "Old"})]
    extra = [Service(port=80, protocol="tcp", name="http", nse_output={"http-methods": "GET, POST"})]
    merged = _merge_nse(base, extra)
    assert "http-title" in merged[0].nse_output
    assert "http-methods" in merged[0].nse_output

def test_merge_nse_no_match():
    base = [Service(port=80, protocol="tcp", name="http")]
    extra = [Service(port=443, protocol="tcp", name="https")]
    merged = _merge_nse(base, extra)
    assert merged[0].nse_output == {}


# --- ServiceEnumModule ---

@pytest.mark.asyncio
async def test_servicenum_run_basic():
    mod = ServiceEnumModule()
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    mock_services = [
        Service(port=22, protocol="tcp", name="ssh", version="OpenSSH 8.9"),
        Service(port=80, protocol="tcp", name="http", version="Apache 2.4.52"),
    ]

    with (
        patch("mylilpwny.modules.servicenum._run_nmap_sv", new_callable=AsyncMock,
              return_value=(mock_services, "<nmaprun/>")),
        patch("mylilpwny.modules.servicenum._run_nmap_scripts", new_callable=AsyncMock,
              return_value=([], "")),
        patch("mylilpwny.modules.servicenum._banner_grab", return_value=None),
    ):
        result = await mod.run(target, {"ports": "22,80", "banner_grab": False})

    assert result.status == "success"
    assert len(result.parsed_findings) == 2

@pytest.mark.asyncio
async def test_servicenum_banner_grab_for_unknown():
    mod = ServiceEnumModule()
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    mock_services = [Service(port=9999, protocol="tcp", name="unknown")]

    with (
        patch("mylilpwny.modules.servicenum._run_nmap_sv", new_callable=AsyncMock,
              return_value=(mock_services, "<nmaprun/>")),
        patch("mylilpwny.modules.servicenum._run_nmap_scripts", new_callable=AsyncMock,
              return_value=([], "")),
        patch("mylilpwny.modules.servicenum._banner_grab", return_value="Custom Service v1.0"),
    ):
        result = await mod.run(target, {"ports": "9999"})

    assert result.parsed_findings[0]["banner"] == "Custom Service v1.0"

def test_servicenum_attributes():
    mod = ServiceEnumModule()
    assert mod.name == "servicenum"
    assert mod.risk_level == "medium"
