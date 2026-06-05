from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from mylilpwny.core.state import Target
from mylilpwny.logging import get_logger
from mylilpwny.modules.base import BaseModule, ModuleResult

log = get_logger(__name__)

# Header → technology mappings for passive fingerprinting
_HEADER_TECH: dict[str, str] = {
    "x-powered-by": "",           # value is the tech (e.g. "PHP/8.1")
    "server": "",                  # value is the tech (e.g. "Apache/2.4.52")
    "x-generator": "",
    "x-drupal-cache": "Drupal",
    "x-wordpress-cache": "WordPress",
    "x-shopify-stage": "Shopify",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "cf-ray": "Cloudflare",
    "x-vercel-id": "Vercel",
    "x-amz-cf-id": "AWS CloudFront",
}

# HTML patterns for tech detection
_HTML_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I), ""),
    (re.compile(r'wp-content/', re.I), "WordPress"),
    (re.compile(r'Joomla!', re.I), "Joomla"),
    (re.compile(r'__VIEWSTATE', re.I), "ASP.NET"),
    (re.compile(r'laravel_session', re.I), "Laravel"),
    (re.compile(r'django', re.I), "Django"),
    (re.compile(r'react(?:\.min)?\.js', re.I), "React"),
    (re.compile(r'vue(?:\.min)?\.js', re.I), "Vue.js"),
    (re.compile(r'angular(?:\.min)?\.js', re.I), "Angular"),
]

_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


@dataclass
class WebFingerprint:
    url: str
    status: int
    title: str | None = None
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "title": self.title,
            "technologies": self.technologies,
            "headers": self.headers,
            "redirect_chain": self.redirect_chain,
            "directories": self.directories,
        }


def _extract_title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
    return m.group(1).strip() if m else None


def _fingerprint_from_response(resp: httpx.Response, html: str) -> list[str]:
    techs: set[str] = set()

    for header, static_tech in _HEADER_TECH.items():
        value = resp.headers.get(header, "")
        if value:
            techs.add(static_tech if static_tech else value)

    for pattern, static_tech in _HTML_PATTERNS:
        m = pattern.search(html)
        if m:
            techs.add(static_tech if static_tech else m.group(1).strip())

    return sorted(t for t in techs if t)


async def _probe_url(url: str, timeout: float = 10.0) -> WebFingerprint | None:
    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": "mylilpwny/0.1"},
        ) as client:
            resp = await client.get(url)
            html = resp.text

            redirect_chain = [str(r.url) for r in resp.history]
            headers = dict(resp.headers)
            title = _extract_title(html)
            techs = _fingerprint_from_response(resp, html)

            return WebFingerprint(
                url=str(resp.url),
                status=resp.status_code,
                title=title,
                technologies=techs,
                headers=headers,
                redirect_chain=redirect_chain,
            )
    except Exception as e:
        log.warning("http probe failed", url=url, error=str(e))
        return None


async def _run_whatweb(url: str, timeout: int = 30) -> list[str]:
    if not shutil.which("whatweb"):
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "whatweb", "--color=never", "--log-brief=-", url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        line = stdout.decode().strip()
        # whatweb brief output: URL [status] Tech1, Tech2[version], ...
        techs: list[str] = []
        if "[" in line:
            parts = line.split("]", 1)[-1].strip()
            techs = [t.strip() for t in parts.split(",") if t.strip()]
        return techs
    except Exception as e:
        log.warning("whatweb failed", error=str(e))
        return []


def _find_wordlist() -> str | None:
    return next((w for w in _WORDLISTS if shutil.which("ffuf") or shutil.which("gobuster")), None)


async def _run_ffuf(url: str, wordlist: str, timeout: int, threads: int = 40) -> list[str]:
    import os
    if not shutil.which("ffuf") or not os.path.exists(wordlist):
        return []
    base = url.rstrip("/")
    cmd = [
        "ffuf", "-u", f"{base}/FUZZ",
        "-w", wordlist,
        "-t", str(threads),
        "-mc", "200,204,301,302,307,401,403,405",
        "-o", "/dev/stdout", "-of", "json",
        "-s",
    ]
    log.info("running ffuf", url=base, wordlist=wordlist)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        data = json.loads(stdout.decode() or "{}")
        return [r["url"] for r in data.get("results", [])]
    except Exception as e:
        log.warning("ffuf failed", error=str(e))
        return []


async def _run_gobuster_dir(url: str, wordlist: str, timeout: int) -> list[str]:
    import os
    if not shutil.which("gobuster") or not os.path.exists(wordlist):
        return []
    cmd = [
        "gobuster", "dir",
        "-u", url, "-w", wordlist,
        "-q", "--no-color",
        "-s", "200,204,301,302,307,401,403",
    ]
    log.info("running gobuster dir", url=url)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        dirs: list[str] = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if line.startswith("/"):
                dirs.append(line.split(" ")[0])
        return dirs
    except Exception as e:
        log.warning("gobuster dir failed", error=str(e))
        return []


class WebEnumModule(BaseModule):
    name = "webnum"
    description = "Web fingerprinting (httpx + whatweb) and directory brute-forcing (ffuf)"
    risk_level = "medium"

    def check_dependencies(self) -> list[str]:
        missing = []
        for tool in ("ffuf", "gobuster"):
            if not self._tool_available(tool):
                missing.append(tool)
        return missing

    async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
        start = time.monotonic()
        ports: list[int] = options.get("ports", [80, 443, 8080, 8443])
        brute_force: bool = options.get("brute_force", False)
        bf_timeout: int = int(options.get("bf_timeout", 120))
        wordlist: str = options.get("wordlist", "")

        ip = target.ip or target.input
        fingerprints: list[WebFingerprint] = []

        # Build URL list from ports
        urls: list[str] = []
        for port in ports:
            scheme = "https" if port in (443, 8443) else "http"
            urls.append(f"{scheme}://{ip}:{port}" if port not in (80, 443) else f"{scheme}://{ip}")

        # Probe all URLs in parallel
        probes = await asyncio.gather(*[_probe_url(url) for url in urls], return_exceptions=True)
        active: list[WebFingerprint] = []
        for fp in probes:
            if isinstance(fp, WebFingerprint):
                active.append(fp)
                fingerprints.append(fp)

        log.info("web probe done", active=len(active), total=len(urls))

        # whatweb enrichment on active URLs
        if active:
            whatweb_results = await asyncio.gather(*[_run_whatweb(fp.url) for fp in active])
            for fp, ww_techs in zip(active, whatweb_results):
                fp.technologies = sorted(set(fp.technologies + ww_techs))

        # Directory brute-force (opt-in, risk_level = high)
        if brute_force and active:
            wl = wordlist or next((w for w in _WORDLISTS if __import__("os").path.exists(w)), "")
            if wl:
                for fp in active:
                    dirs = await _run_ffuf(fp.url, wl, bf_timeout)
                    if not dirs:
                        dirs = await _run_gobuster_dir(fp.url, wl, bf_timeout)
                    fp.directories = dirs
                    log.info("dir brute-force done", url=fp.url, found=len(dirs))
            else:
                log.warning("no wordlist found for brute-force")

        duration = time.monotonic() - start
        log.info("webnum complete", fingerprints=len(fingerprints), duration=round(duration, 2))

        return ModuleResult(
            status="success",
            raw_output=str([fp.to_dict() for fp in fingerprints]),
            parsed_findings=[fp.to_dict() for fp in fingerprints],
            duration=duration,
            command_run=f"httpx+whatweb+ffuf {ip}",
        )
