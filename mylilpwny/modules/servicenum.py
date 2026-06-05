from __future__ import annotations

import asyncio
import socket
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from mylilpwny.core.state import Target
from mylilpwny.logging import get_logger
from mylilpwny.modules.base import BaseModule, ModuleResult

log = get_logger(__name__)

# NSE scripts run in addition to -sC per detected service name
_SERVICE_SCRIPTS: dict[str, list[str]] = {
    "http":     ["http-title", "http-headers", "http-methods", "http-server-header"],
    "https":    ["http-title", "http-headers", "ssl-cert", "ssl-enum-ciphers"],
    "ssl":      ["ssl-cert", "ssl-enum-ciphers"],
    "ftp":      ["ftp-anon", "ftp-syst", "ftp-bounce"],
    "ssh":      ["ssh-hostkey", "ssh2-enum-algos"],
    "smtp":     ["smtp-commands", "smtp-open-relay"],
    "smb":      ["smb-security-mode", "smb-vuln-ms17-010", "smb-enum-shares"],
    "microsoft-ds": ["smb-security-mode", "smb-vuln-ms17-010", "smb-enum-shares"],
    "mysql":    ["mysql-info", "mysql-empty-password"],
    "ms-sql-s": ["ms-sql-info", "ms-sql-empty-password"],
    "rdp":      ["rdp-enum-encryption"],
    "vnc":      ["vnc-info", "vnc-brute"],
    "telnet":   ["telnet-ntlm-info"],
}


@dataclass
class Service:
    port: int
    protocol: str
    name: str
    version: str | None = None
    banner: str | None = None
    nse_output: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "name": self.name,
            "version": self.version,
            "banner": self.banner,
            "nse_output": self.nse_output,
        }


def _parse_nmap_services(xml_str: str) -> list[Service]:
    services: list[Service] = []
    try:
        root = ET.fromstring(xml_str)
        for host in root.findall("host"):
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") not in ("open", "filtered"):
                    continue

                portid = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")

                svc_el = port_el.find("service")
                name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                extra = svc_el.get("extrainfo", "") if svc_el is not None else ""
                full_version = " ".join(filter(None, [product, version, extra])) or None

                # Collect NSE script output
                nse: dict[str, str] = {}
                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    output = script_el.get("output", "").strip()
                    if script_id and output:
                        nse[script_id] = output

                services.append(Service(
                    port=portid,
                    protocol=proto,
                    name=name,
                    version=full_version,
                    nse_output=nse,
                ))
    except Exception as e:
        log.warning("nmap service parse error", error=str(e))
    return services


def _select_scripts(services: list[Service]) -> list[str]:
    """Build deduplicated NSE script list based on detected service names."""
    scripts: set[str] = set()
    for svc in services:
        for key, script_list in _SERVICE_SCRIPTS.items():
            if key in svc.name.lower():
                scripts.update(script_list)
    return sorted(scripts)


async def _run_nmap_sv(ip: str, ports: str, timing: str, timeout: int) -> tuple[list[Service], str]:
    cmd = ["nmap", "-sT", "-sV", "-sC", "-T", timing, "-p", ports, ip, "-oX", "-", "--open"]
    log.info("nmap -sV -sC", cmd=" ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        raw = stdout.decode()
        return _parse_nmap_services(raw), raw
    except asyncio.TimeoutError:
        log.warning("nmap -sV timed out")
        return [], ""
    except Exception as e:
        log.warning("nmap -sV failed", error=str(e))
        return [], ""


async def _run_nmap_scripts(ip: str, ports: str, scripts: list[str], timing: str, timeout: int) -> tuple[list[Service], str]:
    script_arg = ",".join(scripts)
    cmd = ["nmap", "-sT", "-T", timing, "-p", ports, "--script", script_arg, ip, "-oX", "-", "--open"]
    log.info("nmap targeted scripts", scripts=script_arg)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        raw = stdout.decode()
        return _parse_nmap_services(raw), raw
    except asyncio.TimeoutError:
        log.warning("nmap scripts timed out")
        return [], ""
    except Exception as e:
        log.warning("nmap scripts failed", error=str(e))
        return [], ""


def _banner_grab(ip: str, port: int, timeout: float = 3.0) -> str | None:
    """Grab a raw banner from a TCP port via socket."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Send a generic HTTP request to provoke a response on web ports
            if port in (80, 8080, 8000, 8443):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def _merge_nse(base: list[Service], extra: list[Service]) -> list[Service]:
    """Merge NSE output from extra scan into base services."""
    extra_map = {(s.port, s.protocol): s for s in extra}
    for svc in base:
        key = (svc.port, svc.protocol)
        if key in extra_map:
            svc.nse_output.update(extra_map[key].nse_output)
    return base


class ServiceEnumModule(BaseModule):
    name = "servicenum"
    description = "Service detection with nmap -sV -sC and targeted NSE scripts per service type"
    risk_level = "medium"

    def check_dependencies(self) -> list[str]:
        return []  # nmap is required globally

    async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
        start = time.monotonic()
        ip = target.ip or target.input
        ports = str(options.get("ports", "1-65535"))
        timing = str(options.get("timing", "4"))
        enum_timeout = int(options.get("timeout", 120))
        banner_grab = bool(options.get("banner_grab", True))

        raw_parts: list[str] = []

        # Phase 1: -sV -sC to identify services and run default scripts
        services, raw1 = await _run_nmap_sv(ip, ports, timing, enum_timeout)
        raw_parts.append(f"=== nmap -sV -sC ===\n{raw1}")
        log.info("service detection done", count=len(services))

        # Phase 2: targeted NSE scripts based on what we found
        extra_scripts = _select_scripts(services)
        if extra_scripts:
            port_list = ",".join(str(s.port) for s in services)
            _, raw2 = await _run_nmap_scripts(ip, port_list, extra_scripts, timing, enum_timeout)
            raw_parts.append(f"=== nmap targeted scripts ===\n{raw2}")
            extra_services, _ = await _run_nmap_sv(ip, port_list, timing, enum_timeout)
            services = _merge_nse(services, extra_services)

        # Phase 3: banner grabbing for services with unknown name or no version
        if banner_grab:
            for svc in services:
                if svc.version is None or svc.name == "unknown":
                    banner = _banner_grab(ip, svc.port)
                    if banner:
                        svc.banner = banner[:512]  # cap at 512 chars
                        log.info("banner grabbed", port=svc.port, banner=svc.banner[:80])

        duration = time.monotonic() - start
        log.info("servicenum complete", services=len(services), duration=round(duration, 2))

        return ModuleResult(
            status="success",
            raw_output="\n".join(raw_parts),
            parsed_findings=[s.to_dict() for s in services],
            duration=duration,
            command_run=f"nmap -sT -sV -sC -p {ports} {ip}",
        )
