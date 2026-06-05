from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from mylilpwny.core.state import Target
from mylilpwny.logging import get_logger
from mylilpwny.modules.base import BaseModule, ModuleResult

log = get_logger(__name__)

Severity = Literal["info", "low", "medium", "high", "critical"]

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_TIMEOUT = 10.0
_NVD_RATE_DELAY = 6.0  # 5 req/30s without API key → ~6s between calls


def _cvss_to_severity(score: float) -> Severity:
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


@dataclass
class Vulnerability:
    service: str
    cve: str | None
    cvss: float | None
    severity: Severity
    description: str
    exploit_available: bool
    source: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "cve": self.cve,
            "cvss": self.cvss,
            "severity": self.severity,
            "description": self.description,
            "exploit_available": self.exploit_available,
            "source": self.source,
            "references": self.references,
        }


def _parse_searchsploit_json(raw: str, service_label: str) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    try:
        data = json.loads(raw)
        for entry in data.get("RESULTS_EXPLOIT", []):
            title = entry.get("Title", "")
            edb_id = entry.get("EDB-ID", "")
            path = entry.get("Path", "")
            vulns.append(Vulnerability(
                service=service_label,
                cve=None,
                cvss=None,
                severity="medium",
                description=title,
                exploit_available=True,
                source="searchsploit",
                references=[f"https://www.exploit-db.com/exploits/{edb_id}", path],
            ))
    except Exception as e:
        log.warning("searchsploit parse error", error=str(e))
    return vulns


async def _run_searchsploit(service: str, version: str, timeout: int = 15) -> list[Vulnerability]:
    query = f"{service} {version}".strip()
    if not query:
        return []
    cmd = ["searchsploit", "--json", "-t", query]
    log.info("searchsploit query", query=query)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return _parse_searchsploit_json(stdout.decode(), query)
    except FileNotFoundError:
        log.warning("searchsploit not installed")
        return []
    except asyncio.TimeoutError:
        log.warning("searchsploit timed out", query=query)
        return []
    except Exception as e:
        log.warning("searchsploit failed", error=str(e))
        return []


def _extract_nvd_vulns(data: dict[str, Any], service_label: str) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Description (English preferred)
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS score — prefer v3.1, fall back to v3.0, then v2
        cvss: float | None = None
        severity: Severity = "info"
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    cvss = float(score)
                    severity = _cvss_to_severity(cvss)
                    break

        refs = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")]

        vulns.append(Vulnerability(
            service=service_label,
            cve=cve_id,
            cvss=cvss,
            severity=severity,
            description=desc[:500],
            exploit_available=False,
            source="nvd",
            references=refs[:5],
        ))
    return vulns


async def _query_nvd(keyword: str, service_label: str) -> list[Vulnerability]:
    if not keyword.strip():
        return []
    log.info("nvd query", keyword=keyword)
    try:
        async with httpx.AsyncClient(timeout=_NVD_TIMEOUT) as client:
            resp = await client.get(_NVD_API, params={"keywordSearch": keyword, "resultsPerPage": 10})
            if resp.status_code != 200:
                log.warning("nvd api error", status=resp.status_code)
                return []
            return _extract_nvd_vulns(resp.json(), service_label)
    except Exception as e:
        log.warning("nvd query failed", error=str(e))
        return []


def _deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
    seen_cves: set[str] = set()
    seen_descs: set[str] = set()
    out: list[Vulnerability] = []
    for v in sorted(vulns, key=lambda x: x.cvss or 0.0, reverse=True):
        key = v.cve or v.description[:80]
        if v.cve and v.cve in seen_cves:
            continue
        if not v.cve and key in seen_descs:
            continue
        if v.cve:
            seen_cves.add(v.cve)
        else:
            seen_descs.add(key)
        out.append(v)
    return out


class VulnAnalysisModule(BaseModule):
    name = "vulnanalysis"
    description = "Vulnerability analysis via searchsploit and NVD API — maps CVEs to CVSS scores"
    risk_level = "low"

    def check_dependencies(self) -> list[str]:
        return [] if self._tool_available("searchsploit") else ["searchsploit"]

    async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
        start = time.monotonic()

        # services: list of dicts with "name" and optional "version"
        services: list[dict[str, Any]] = options.get("services", [])
        use_nvd: bool = options.get("use_nvd", True)
        nvd_delay: float = float(options.get("nvd_delay", _NVD_RATE_DELAY))

        if not services:
            log.warning("no services provided to vulnanalysis")
            return ModuleResult(
                status="skipped",
                raw_output="",
                parsed_findings=[],
                duration=0.0,
                command_run=None,
                error="no services to analyse",
            )

        all_vulns: list[Vulnerability] = []

        for svc in services:
            name: str = svc.get("name", "")
            version: str = svc.get("version") or ""
            label = f"{name} {version}".strip()
            if not name or name == "unknown":
                continue

            log.info("analysing service", service=label)

            # searchsploit — local, fast
            ss_vulns = await _run_searchsploit(name, version)
            all_vulns.extend(ss_vulns)

            # NVD API — remote, rate limited
            if use_nvd:
                nvd_vulns = await _query_nvd(label, label)
                all_vulns.extend(nvd_vulns)
                await asyncio.sleep(nvd_delay)

        deduped = _deduplicate(all_vulns)
        duration = time.monotonic() - start
        log.info("vulnanalysis complete", total=len(deduped), duration=round(duration, 2))

        return ModuleResult(
            status="success",
            raw_output=str([v.to_dict() for v in deduped]),
            parsed_findings=[v.to_dict() for v in deduped],
            duration=duration,
            command_run="searchsploit + nvd api",
        )
