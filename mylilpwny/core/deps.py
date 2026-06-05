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
    ToolSpec(
        name="nmap",
        required=True,
        description="Port scanning and service detection",
        install_hint="pacman -S nmap  |  apt install nmap",
    ),
    ToolSpec(
        name="masscan",
        required=False,
        description="Fast port sweep (falls back to nmap if missing)",
        install_hint="pacman -S masscan  |  apt install masscan",
    ),
    ToolSpec(
        name="whatweb",
        required=False,
        description="Web technology fingerprinting",
        install_hint="pacman -S whatweb  |  apt install whatweb",
    ),
    ToolSpec(
        name="feroxbuster",
        required=False,
        description="Directory and file brute-forcing",
        install_hint="pacman -S feroxbuster  |  cargo install feroxbuster",
    ),
    ToolSpec(
        name="searchsploit",
        required=False,
        description="Exploit database search (part of exploitdb)",
        install_hint="pacman -S exploitdb  |  apt install exploitdb",
    ),
    ToolSpec(
        name="subfinder",
        required=False,
        description="Subdomain enumeration",
        install_hint="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    ToolSpec(
        name="nuclei",
        required=False,
        description="Vulnerability scanner (used in bug bounty mode)",
        install_hint="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    ToolSpec(
        name="httpx",
        required=False,
        description="HTTP probing and fingerprinting",
        install_hint="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ),
]


def check_all() -> list[ToolStatus]:
    return [ToolStatus(spec=t, path=shutil.which(t.name)) for t in TOOLS]


def missing_required(statuses: list[ToolStatus]) -> list[ToolStatus]:
    return [s for s in statuses if s.spec.required and not s.installed]
