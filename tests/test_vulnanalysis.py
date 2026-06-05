from unittest.mock import AsyncMock, patch

import pytest

from mylilpwny.core.state import Target
from mylilpwny.modules.vulnanalysis import (
    Vulnerability,
    VulnAnalysisModule,
    _cvss_to_severity,
    _deduplicate,
    _extract_nvd_vulns,
    _parse_searchsploit_json,
)

# --- severity mapping ---

def test_cvss_critical():
    assert _cvss_to_severity(9.8) == "critical"

def test_cvss_high():
    assert _cvss_to_severity(8.1) == "high"

def test_cvss_medium():
    assert _cvss_to_severity(5.3) == "medium"

def test_cvss_low():
    assert _cvss_to_severity(2.1) == "low"

def test_cvss_info():
    assert _cvss_to_severity(0.0) == "info"


# --- searchsploit parser ---

SS_JSON = """{
  "RESULTS_EXPLOIT": [
    {
      "Title": "Apache 2.4.49 - Path Traversal & RCE",
      "EDB-ID": "50383",
      "Date": "2021-10-07",
      "Author": "Ash",
      "Type": "webapps",
      "Platform": "multiple",
      "Path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.py"
    }
  ],
  "RESULTS_SHELLCODE": []
}"""

def test_parse_searchsploit_basic():
    vulns = _parse_searchsploit_json(SS_JSON, "Apache 2.4.49")
    assert len(vulns) == 1
    v = vulns[0]
    assert "Path Traversal" in v.description
    assert v.exploit_available is True
    assert v.source == "searchsploit"
    assert any("50383" in r for r in v.references)

def test_parse_searchsploit_empty():
    assert _parse_searchsploit_json('{"RESULTS_EXPLOIT": []}', "test") == []

def test_parse_searchsploit_invalid():
    assert _parse_searchsploit_json("not json", "test") == []


# --- NVD parser ---

NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {"lang": "en", "value": "A path traversal in Apache 2.4.49..."},
                    {"lang": "es", "value": "..."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                    ]
                },
                "references": [
                    {"url": "https://httpd.apache.org/security/vulnerabilities_24.html"},
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
                ],
            }
        }
    ]
}

def test_extract_nvd_cve_id():
    vulns = _extract_nvd_vulns(NVD_RESPONSE, "Apache 2.4.49")
    assert len(vulns) == 1
    assert vulns[0].cve == "CVE-2021-41773"

def test_extract_nvd_cvss():
    vulns = _extract_nvd_vulns(NVD_RESPONSE, "Apache 2.4.49")
    assert vulns[0].cvss == 7.5
    assert vulns[0].severity == "high"

def test_extract_nvd_description():
    vulns = _extract_nvd_vulns(NVD_RESPONSE, "Apache 2.4.49")
    assert "path traversal" in vulns[0].description.lower()

def test_extract_nvd_references():
    vulns = _extract_nvd_vulns(NVD_RESPONSE, "Apache 2.4.49")
    assert len(vulns[0].references) == 2

def test_extract_nvd_empty():
    assert _extract_nvd_vulns({"vulnerabilities": []}, "test") == []


# --- deduplication ---

def _vuln(cve: str | None, cvss: float, desc: str = "") -> Vulnerability:
    return Vulnerability(
        service="test", cve=cve, cvss=cvss,
        severity=_cvss_to_severity(cvss),
        description=desc or (cve or "desc"),
        exploit_available=False, source="nvd",
    )

def test_deduplicate_removes_same_cve():
    vulns = [_vuln("CVE-2021-41773", 7.5), _vuln("CVE-2021-41773", 7.5)]
    assert len(_deduplicate(vulns)) == 1

def test_deduplicate_sorts_by_cvss():
    vulns = [_vuln("CVE-001", 5.0), _vuln("CVE-002", 9.8), _vuln("CVE-003", 3.1)]
    deduped = _deduplicate(vulns)
    assert deduped[0].cvss == 9.8

def test_deduplicate_keeps_different_cves():
    vulns = [_vuln("CVE-001", 7.0), _vuln("CVE-002", 5.0)]
    assert len(_deduplicate(vulns)) == 2

def test_deduplicate_no_cve_by_desc():
    vulns = [_vuln(None, 5.0, "Same exploit"), _vuln(None, 5.0, "Same exploit")]
    assert len(_deduplicate(vulns)) == 1


# --- VulnAnalysisModule ---

@pytest.mark.asyncio
async def test_vulnanalysis_no_services():
    mod = VulnAnalysisModule()
    target = Target(input="10.0.0.1")
    result = await mod.run(target, {})
    assert result.status == "skipped"

@pytest.mark.asyncio
async def test_vulnanalysis_skips_unknown_service():
    mod = VulnAnalysisModule()
    target = Target(input="10.0.0.1")
    with (
        patch("mylilpwny.modules.vulnanalysis._run_searchsploit", new_callable=AsyncMock, return_value=[]) as mock_ss,
        patch("mylilpwny.modules.vulnanalysis._query_nvd", new_callable=AsyncMock, return_value=[]),
    ):
        result = await mod.run(target, {"services": [{"name": "unknown", "version": None}]})
        mock_ss.assert_not_called()
    assert result.status == "success"

@pytest.mark.asyncio
async def test_vulnanalysis_run_returns_findings():
    mod = VulnAnalysisModule()
    target = Target(input="10.0.0.1")

    mock_vuln = Vulnerability(
        service="Apache 2.4.49", cve="CVE-2021-41773", cvss=7.5,
        severity="high", description="Path traversal", exploit_available=True, source="searchsploit",
    )

    with (
        patch("mylilpwny.modules.vulnanalysis._run_searchsploit", new_callable=AsyncMock, return_value=[mock_vuln]),
        patch("mylilpwny.modules.vulnanalysis._query_nvd", new_callable=AsyncMock, return_value=[]),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await mod.run(target, {
            "services": [{"name": "http", "version": "Apache 2.4.49"}],
            "nvd_delay": 0,
        })

    assert result.status == "success"
    assert result.parsed_findings[0]["cve"] == "CVE-2021-41773"
    assert result.parsed_findings[0]["cvss"] == 7.5

def test_vulnanalysis_attributes():
    mod = VulnAnalysisModule()
    assert mod.name == "vulnanalysis"
    assert mod.risk_level == "low"
