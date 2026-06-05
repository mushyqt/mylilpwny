from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mylilpwny.core.state import Target
from mylilpwny.modules.recon import (
    ReconModule,
    ReconResult,
    _asn_lookup,
    _resolve_dns,
    _whois_lookup,
)


def test_recon_result_to_dict():
    r = ReconResult(ips=["1.2.3.4"], hostnames=["example.com"], asn="AS12345")
    d = r.to_dict()
    assert d["ips"] == ["1.2.3.4"]
    assert d["asn"] == "AS12345"
    assert d["subdomains"] == []


def test_resolve_dns_returns_tuples():
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([MagicMock(__str__=lambda s: "1.2.3.4")]))
        mock_resolve.return_value = mock_answer
        hostnames, ips = _resolve_dns("example.com")
        assert isinstance(hostnames, list)
        assert isinstance(ips, list)


def test_resolve_dns_failure_returns_empty():
    with patch("dns.resolver.Resolver.resolve", side_effect=Exception("fail")):
        hostnames, ips = _resolve_dns("nonexistent.invalid")
        assert hostnames == []
        assert ips == []


def test_whois_lookup_failure_returns_empty():
    with patch("whois.whois", side_effect=Exception("fail")):
        registrar, emails = _whois_lookup("example.com")
        assert registrar is None
        assert emails == []


def test_asn_lookup_failure_returns_none():
    with patch("ipwhois.IPWhois.lookup_rdap", side_effect=Exception("fail")):
        asn, desc = _asn_lookup("1.2.3.4")
        assert asn is None
        assert desc is None


@pytest.mark.asyncio
async def test_recon_module_run_no_tools():
    mod = ReconModule()
    target = Target(input="1.2.3.4")

    with (
        patch("mylilpwny.modules.recon._resolve_dns", return_value=([], ["1.2.3.4"])),
        patch("mylilpwny.modules.recon._whois_lookup", return_value=(None, [])),
        patch("mylilpwny.modules.recon._asn_lookup", return_value=("AS1234", "Test ISP")),
        patch("mylilpwny.modules.recon._run_amass", new_callable=AsyncMock, return_value=[]),
        patch("mylilpwny.modules.recon._run_gobuster_dns", new_callable=AsyncMock, return_value=[]),
    ):
        result = await mod.run(target, {})

    assert result.status == "success"
    assert result.duration > 0


@pytest.mark.asyncio
async def test_recon_module_merges_subdomains():
    mod = ReconModule()
    target = Target(input="example.com", hostname="example.com")

    with (
        patch("mylilpwny.modules.recon._resolve_dns", return_value=(["example.com"], ["1.2.3.4"])),
        patch("mylilpwny.modules.recon._whois_lookup", return_value=("Registrar Inc", ["admin@example.com"])),
        patch("mylilpwny.modules.recon._asn_lookup", return_value=("AS999", "Some ISP")),
        patch("mylilpwny.modules.recon._run_amass", new_callable=AsyncMock, return_value=["a.example.com", "b.example.com"]),
        patch("mylilpwny.modules.recon._run_gobuster_dns", new_callable=AsyncMock, return_value=["b.example.com", "c.example.com"]),
    ):
        result = await mod.run(target, {})

    assert result.status == "success"
    findings = result.parsed_findings[0]
    assert sorted(findings["subdomains"]) == ["a.example.com", "b.example.com", "c.example.com"]
    assert findings["registrar"] == "Registrar Inc"


def test_recon_module_attributes():
    mod = ReconModule()
    assert mod.name == "recon"
    assert mod.risk_level == "low"
