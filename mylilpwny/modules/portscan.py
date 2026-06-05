from __future__ import annotations

import asyncio
import json
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from mylilpwny.core.state import Target
from mylilpwny.logging import get_logger
from mylilpwny.modules.base import BaseModule, ModuleResult

log = get_logger(__name__)


@dataclass
class OpenPort:
    port: int
    protocol: str
    state: str
    service: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
        }


def _parse_masscan_json(raw: str) -> list[OpenPort]:
    ports: list[OpenPort] = []
    try:
        # masscan JSON can have a trailing comma before ] — strip it
        cleaned = raw.strip().rstrip(",")
        if not cleaned or cleaned == "[]":
            return []
        data = json.loads(cleaned)
        for host in data:
            for p in host.get("ports", []):
                if p.get("status") == "open":
                    ports.append(OpenPort(
                        port=int(p["port"]),
                        protocol=p.get("proto", "tcp"),
                        state="open",
                    ))
    except Exception as e:
        log.warning("masscan parse error", error=str(e))
    return ports


def _parse_nmap_xml(xml_str: str) -> list[OpenPort]:
    ports: list[OpenPort] = []
    try:
        root = ET.fromstring(xml_str)
        for host in root.findall("host"):
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None:
                    continue
                state = state_el.get("state", "")
                if state not in ("open", "filtered"):
                    continue
                svc_el = port_el.find("service")
                service = svc_el.get("name") if svc_el is not None else None
                ports.append(OpenPort(
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    state=state,
                    service=service,
                ))
    except Exception as e:
        log.warning("nmap xml parse error", error=str(e))
    return ports


async def _run_masscan(ip: str, ports: str, rate: int, timeout: int) -> tuple[list[OpenPort], str]:
    """Run masscan and return (open_ports, raw_output). Falls back to [] on permission error."""
    cmd = ["masscan", "--rate", str(rate), "-p", ports, ip, "-oJ", "-", "--wait", "2"]
    log.info("running masscan", cmd=" ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        raw = stdout.decode()
        err = stderr.decode()

        if "permission denied" in err.lower() or "failed to detect" in err.lower():
            log.warning("masscan requires root — falling back to nmap-only")
            return [], ""

        return _parse_masscan_json(raw), raw
    except asyncio.TimeoutError:
        log.warning("masscan timed out", timeout=timeout)
        return [], ""
    except Exception as e:
        log.warning("masscan failed", error=str(e))
        return [], ""


async def _run_nmap(ip: str, ports: str, timing: str, timeout: int) -> tuple[list[OpenPort], str]:
    """Run nmap on given ports and return (ports, raw_xml)."""
    # Use -sT (connect scan) so it works without root when needed
    cmd = ["nmap", "-sT", "-sV", "--version-intensity", "0",
           "-T", timing, "-p", ports, ip, "-oX", "-", "--open"]
    log.info("running nmap", cmd=" ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        raw = stdout.decode()
        return _parse_nmap_xml(raw), raw
    except asyncio.TimeoutError:
        log.warning("nmap timed out", timeout=timeout)
        return [], ""
    except Exception as e:
        log.warning("nmap failed", error=str(e))
        return [], ""


class PortScanModule(BaseModule):
    name = "portscan"
    description = "Two-phase port scan: masscan fast sweep → nmap confirmation and service detection"
    risk_level = "medium"

    def check_dependencies(self) -> list[str]:
        # masscan optional — nmap is required (checked globally)
        return []

    async def run(self, target: Target, options: dict[str, Any]) -> ModuleResult:
        start = time.monotonic()
        ip = target.ip or target.input
        ports = str(options.get("ports", "1-65535"))
        rate = int(options.get("rate", 1000))
        timing = str(options.get("timing", "4"))
        scan_timeout = int(options.get("timeout", 300))

        raw_parts: list[str] = []
        open_ports: list[OpenPort] = []

        use_masscan = shutil.which("masscan") is not None

        if use_masscan:
            log.info("phase 1: masscan sweep", ports=ports, rate=rate)
            masscan_ports, masscan_raw = await _run_masscan(ip, ports, rate, timeout=scan_timeout)
            raw_parts.append(f"=== masscan ===\n{masscan_raw}")

            if masscan_ports:
                # Phase 2: nmap on ports masscan found
                port_list = ",".join(str(p.port) for p in masscan_ports)
                log.info("phase 2: nmap on open ports", ports=port_list, count=len(masscan_ports))
                nmap_ports, nmap_raw = await _run_nmap(ip, port_list, timing, timeout=scan_timeout)
                raw_parts.append(f"=== nmap ===\n{nmap_raw}")
                # Prefer nmap results (richer), fall back to masscan if nmap found nothing
                open_ports = nmap_ports or masscan_ports
            else:
                log.info("masscan found no open ports or failed — running nmap full scan")
                nmap_ports, nmap_raw = await _run_nmap(ip, ports, timing, timeout=scan_timeout)
                raw_parts.append(f"=== nmap ===\n{nmap_raw}")
                open_ports = nmap_ports
        else:
            log.info("masscan not available — nmap-only scan", ports=ports)
            nmap_ports, nmap_raw = await _run_nmap(ip, ports, timing, timeout=scan_timeout)
            raw_parts.append(f"=== nmap ===\n{nmap_raw}")
            open_ports = nmap_ports

        duration = time.monotonic() - start
        log.info("portscan complete", open_ports=len(open_ports), duration=round(duration, 2))

        return ModuleResult(
            status="success",
            raw_output="\n".join(raw_parts),
            parsed_findings=[p.to_dict() for p in open_ports],
            duration=duration,
            command_run=f"masscan+nmap {ip} -p{ports}" if use_masscan else f"nmap {ip} -p{ports}",
        )
