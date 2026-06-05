from unittest.mock import AsyncMock, patch

import pytest

from mylilpwny.core.state import Target
from mylilpwny.modules.portscan import (
    OpenPort,
    PortScanModule,
    _parse_masscan_json,
    _parse_nmap_xml,
)

# --- OpenPort ---

def test_open_port_to_dict():
    p = OpenPort(port=80, protocol="tcp", state="open", service="http")
    d = p.to_dict()
    assert d["port"] == 80
    assert d["service"] == "http"


# --- masscan parser ---

def test_parse_masscan_json_valid():
    raw = '[{"ip":"10.0.0.1","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64}]}]'
    ports = _parse_masscan_json(raw)
    assert len(ports) == 1
    assert ports[0].port == 80
    assert ports[0].state == "open"

def test_parse_masscan_json_filters_closed():
    raw = '[{"ip":"10.0.0.1","ports":[{"port":81,"proto":"tcp","status":"closed","reason":"rst","ttl":64}]}]'
    assert _parse_masscan_json(raw) == []

def test_parse_masscan_json_empty():
    assert _parse_masscan_json("[]") == []

def test_parse_masscan_json_trailing_comma():
    raw = '[{"ip":"10.0.0.1","ports":[{"port":22,"proto":"tcp","status":"open","reason":"syn-ack","ttl":64}]}],'
    ports = _parse_masscan_json(raw)
    assert ports[0].port == 22

def test_parse_masscan_json_invalid():
    assert _parse_masscan_json("not json") == []


# --- nmap parser ---

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

def test_parse_nmap_xml_open_ports():
    ports = _parse_nmap_xml(NMAP_XML)
    assert len(ports) == 2
    assert ports[0].port == 22
    assert ports[0].service == "ssh"
    assert ports[1].port == 80
    assert ports[1].service == "http"

def test_parse_nmap_xml_no_closed():
    ports = _parse_nmap_xml(NMAP_XML)
    assert all(p.state == "open" for p in ports)

def test_parse_nmap_xml_empty():
    assert _parse_nmap_xml("<nmaprun></nmaprun>") == []

def test_parse_nmap_xml_invalid():
    assert _parse_nmap_xml("not xml") == []


# --- PortScanModule ---

@pytest.mark.asyncio
async def test_portscan_nmap_only_no_masscan():
    mod = PortScanModule()
    target = Target(input="127.0.0.1", ip="127.0.0.1")

    mock_ports = [OpenPort(port=22, protocol="tcp", state="open", service="ssh")]

    with (
        patch("shutil.which", return_value=None),  # masscan not available
        patch("mylilpwny.modules.portscan._run_nmap", new_callable=AsyncMock,
              return_value=(mock_ports, "<nmaprun/>")),
    ):
        result = await mod.run(target, {"ports": "22"})

    assert result.status == "success"
    assert len(result.parsed_findings) == 1
    assert result.parsed_findings[0]["port"] == 22


@pytest.mark.asyncio
async def test_portscan_two_phase_masscan_then_nmap():
    mod = PortScanModule()
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    masscan_ports = [OpenPort(port=80, protocol="tcp", state="open")]
    nmap_ports = [OpenPort(port=80, protocol="tcp", state="open", service="http")]

    with (
        patch("shutil.which", return_value="/usr/bin/masscan"),
        patch("mylilpwny.modules.portscan._run_masscan", new_callable=AsyncMock,
              return_value=(masscan_ports, "[]")),
        patch("mylilpwny.modules.portscan._run_nmap", new_callable=AsyncMock,
              return_value=(nmap_ports, "<nmaprun/>")),
    ):
        result = await mod.run(target, {})

    assert result.status == "success"
    assert result.parsed_findings[0]["service"] == "http"


@pytest.mark.asyncio
async def test_portscan_falls_back_when_masscan_finds_nothing():
    mod = PortScanModule()
    target = Target(input="10.0.0.1", ip="10.0.0.1")

    nmap_ports = [OpenPort(port=443, protocol="tcp", state="open", service="https")]

    with (
        patch("shutil.which", return_value="/usr/bin/masscan"),
        patch("mylilpwny.modules.portscan._run_masscan", new_callable=AsyncMock,
              return_value=([], "")),
        patch("mylilpwny.modules.portscan._run_nmap", new_callable=AsyncMock,
              return_value=(nmap_ports, "<nmaprun/>")),
    ):
        result = await mod.run(target, {})

    assert result.parsed_findings[0]["port"] == 443


def test_portscan_attributes():
    mod = PortScanModule()
    assert mod.name == "portscan"
    assert mod.risk_level == "medium"
