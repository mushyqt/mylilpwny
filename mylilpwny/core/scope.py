from __future__ import annotations

import ipaddress
from pathlib import Path


class OutOfScopeError(Exception):
    """Raised when a target is not in scope."""


class ScopeValidator:
    """Validates targets against an in-scope list.

    Supports: IP addresses, CIDR ranges, hostnames, wildcard domains (*.example.com).
    Scope file format: one entry per line, lines starting with # are comments.
    """

    def __init__(self, entries: list[str]) -> None:
        self._raw_entries: list[str] = [e.strip() for e in entries if e.strip() and not e.startswith("#")]
        self._ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._hostnames: set[str] = set()
        self._wildcards: list[str] = []

        for entry in entries:
            self._parse(entry.strip())

    @property
    def entries(self) -> list[str]:
        return list(self._raw_entries)

    def _parse(self, entry: str) -> None:
        if not entry or entry.startswith("#"):
            return

        if entry.startswith("*."):
            self._wildcards.append(entry[2:].lower())
            return

        try:
            if "/" in entry:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            else:
                self._ips.append(ipaddress.ip_address(entry))
            return
        except ValueError:
            pass

        self._hostnames.add(entry.lower())

    def is_in_scope(self, target: str) -> bool:
        target = target.strip().lower()

        try:
            addr = ipaddress.ip_address(target)
            return addr in self._ips or any(addr in net for net in self._networks)
        except ValueError:
            pass

        if target in self._hostnames:
            return True

        return any(target.endswith("." + wc) for wc in self._wildcards)

    def require_in_scope(self, target: str) -> None:
        """Raise OutOfScopeError if target is not in scope."""
        if not self.is_in_scope(target):
            raise OutOfScopeError(f"Target is out of scope: {target}")

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopeValidator":
        lines = Path(path).read_text().splitlines()
        return cls(lines)

    @classmethod
    def from_target(cls, target: str) -> "ScopeValidator":
        return cls([target])
