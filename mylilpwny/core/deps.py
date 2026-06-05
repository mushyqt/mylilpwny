from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass
class ToolSpec:
    name: str
    required: bool
    description: str
    install_hint: str


@dataclass
class ToolStatus:
    spec: ToolSpec
    path: str | None

    @property
    def installed(self) -> bool:
        return self.path is not None


TOOLS: list[ToolSpec] = [
    # --- Required ---
    ToolSpec(
        name="nmap",
        required=True,
        description="Port scanning and service detection",
        install_hint="pacman -S nmap  |  apt install nmap",
    ),
    # --- Recon ---
    ToolSpec(
        name="masscan",
        required=False,
        description="Fast port sweep (falls back to nmap if missing)",
        install_hint="pacman -S masscan  |  apt install masscan",
    ),
    ToolSpec(
        name="amass",
        required=False,
        description="Subdomain enumeration (passive + active)",
        install_hint="pacman -S amass  |  apt install amass",
    ),
    ToolSpec(
        name="gobuster",
        required=False,
        description="DNS subdomain + directory/file brute-forcing",
        install_hint="pacman -S gobuster  |  apt install gobuster",
    ),
    ToolSpec(
        name="ffuf",
        required=False,
        description="Fast web fuzzer for directories, files, and vhosts",
        install_hint="pacman -S ffuf  |  apt install ffuf",
    ),
    # --- Web ---
    ToolSpec(
        name="whatweb",
        required=False,
        description="Web technology fingerprinting",
        install_hint="pacman -S whatweb  |  apt install whatweb",
    ),
    # --- Vuln analysis ---
    ToolSpec(
        name="searchsploit",
        required=False,
        description="Exploit database search (part of exploitdb)",
        install_hint="pacman -S exploitdb  |  apt install exploitdb",
    ),
    # --- Bug bounty (Phase 4) ---
    ToolSpec(
        name="nuclei",
        required=False,
        description="Vulnerability scanner (used in bug bounty mode)",
        install_hint="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
]


def check_all() -> list[ToolStatus]:
    return [ToolStatus(spec=t, path=shutil.which(t.name)) for t in TOOLS]


def missing_required(statuses: list[ToolStatus]) -> list[ToolStatus]:
    return [s for s in statuses if s.spec.required and not s.installed]
