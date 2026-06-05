from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

import dns.resolver
import whois
from ipwhois import IPWhois

from mylilpwny.core.state import Target
from mylilpwny.logging import get_logger
from mylilpwny.modules.base import BaseModule, ModuleResult

log = get_logger(__name__)


@dataclass
class ReconResult:
    hostnames: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    asn: str | None = None
    asn_description: str | None = None
    registrar: str | None = None
    whois_emails: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostnames": self.hostnames,
            "ips": self.ips,
            "subdomains": self.subdomains,
            "asn": self.asn,
            "asn_description": self.asn_description,
            "registrar": self.registrar,
            "whois_emails": self.whois_emails,
        }


def _resolve_dns(target: str) -> tuple[list[str], list[str]]:
    """Return (hostnames, ips). Works for both IPs and hostnames."""
    hostnames: list[str] = []
    ips: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        answers = resolver.resolve(target, "A")
        ips = [str(r) for r in answers]
        hostnames = [target] if not target.replace(".", "").isdigit() else []
    except Exception:
        pass

    try:
        answers = resolver.resolve(target, "AAAA")
        ips += [str(r) for r in answers]
    except Exception:
        pass

    if not hostnames and ips:
        try:
            rev = resolver.resolve(dns.reversename.from_address(ips[0]), "PTR")
            hostnames = [str(r).rstrip(".") for r in rev]
        except Exception:
            pass

    return hostnames, ips


def _whois_lookup(target: str) -> tuple[str | None, list[str]]:
    """Return (registrar, emails)."""
    try:
        w = whois.whois(target)
        registrar = w.registrar if isinstance(w.registrar, str) else None
        emails_raw = w.emails or []
        emails = [emails_raw] if isinstance(emails_raw, str) else list(emails_raw)
        return registrar, emails
    except Exception:
        return None, []


def _asn_lookup(ip: str) -> tuple[str | None, str | None]:
    """Return (asn, description)."""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        asn = result.get("asn")
        desc = result.get("asn_description")
        return str(asn) if asn else None, str(desc) if desc else None
    except Exception:
        return None, None


async def _run_amass(target: str, timeout: int = 60) -> list[str]:
    """Run amass enum passively; return list of subdomains."""
    if not shutil.which("amass"):
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "amass", "enum", "-passive", "-d", target, "-timeout", str(timeout // 60 or 1),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return [line.strip() for line in stdout.decode().splitlines() if line.strip()]
    except Exception:
        return []


async def _run_gobuster_dns(target: str, wordlist: str = "/usr/share/wordlists/dns/subdomains-top1million-5000.txt", timeout: int = 60) -> list[str]:
    """Run gobuster dns mode; return list of subdomains."""
    if not shutil.which("gobuster"):
        return []
    import os
    if not os.path.exists(wordlist):
        # Fallback wordlist paths
        candidates = [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ]
        wordlist = next((p for p in candidates if os.path.exists(p)), "")
    if not wordlist:
        log.warning("gobuster dns: no wordlist found, skipping")
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "gobuster", "dns",
            "-d", target,
            "-w", wordlist,
            "-q", "--no-color",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        subs = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if line.startswith("Found:"):
                subs.append(line.split("Found:")[-1].strip())
        return subs
    except Exception:
        return []


class ReconModule(BaseModule):
    name = "recon"
    description = "DNS resolution, WHOIS, ASN lookup, and subdomain enumeration"
    risk_level = "low"

    def check_dependencies(self) -> list[str]:
        missing = []
        for tool in ("amass", "gobuster"):
            if not self._tool_available(tool):
                missing.append(tool)
        return missing

    async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
        start = time.monotonic()
        result = ReconResult()

        log.info("recon started", target=target.input)

        # DNS
        hostnames, ips = _resolve_dns(target.input)
        result.hostnames = hostnames
        result.ips = ips
        log.info("dns resolved", hostnames=hostnames, ips=ips)

        # WHOIS
        whois_target = hostnames[0] if hostnames else target.input
        registrar, emails = _whois_lookup(whois_target)
        result.registrar = registrar
        result.whois_emails = emails

        # ASN
        if ips:
            asn, desc = _asn_lookup(ips[0])
            result.asn = asn
            result.asn_description = desc
            log.info("asn lookup", asn=asn, description=desc)

        # Subdomain enumeration (only for hostnames, not raw IPs)
        is_hostname = hostnames or not target.input.replace(".", "").isdigit()
        subdomain_target = hostnames[0] if hostnames else target.input if is_hostname else None

        if subdomain_target:
            timeout = options.get("subdomain_timeout", 60)
            amass_subs, gobuster_subs = await asyncio.gather(
                _run_amass(subdomain_target, timeout=int(timeout)),
                _run_gobuster_dns(subdomain_target, timeout=int(timeout)),
            )
            result.subdomains = sorted(set(amass_subs + gobuster_subs))
            log.info("subdomain enum complete", count=len(result.subdomains))

        duration = time.monotonic() - start
        return ModuleResult(
            status="success",
            raw_output=str(result.to_dict()),
            parsed_findings=[result.to_dict()],
            duration=duration,
            command_run="dns+whois+asn+amass+gobuster",
        )
