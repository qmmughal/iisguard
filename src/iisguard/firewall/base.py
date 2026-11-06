"""Firewall backend interface. Backends only BUILD commands; the manager decides whether to run them.

Every sync is two-phase: ``add`` commands for the new generation run first, ``cleanup`` commands for the old
generation run only after the add phase succeeded. If the add phase fails, ``undo`` removes the partial new
generation and the previous rules stay untouched.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class Cmd:
    argv: list[str]
    stdin: str | None = None
    purpose: str = ""
    kind: str = "exec"  # exec | http
    secret_env: str = ""  # name of an env var holding a credential (never printed)
    tag: str = ""  # e.g. the IP an http add-call is for

    def display(self) -> str:
        text = " ".join(self.argv)
        if self.stdin:
            first = self.stdin.strip().splitlines()[0] if self.stdin.strip() else ""
            text += f"   <<stdin: {first[:60]}{'...' if len(self.stdin) > 60 else ''}>>"
        return text


@dataclass
class SyncPlan:
    add: list[Cmd] = field(default_factory=list)
    cleanup: list[Cmd] = field(default_factory=list)
    undo: list[Cmd] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)  # stored in state, needed to clean up this generation


Runner = Callable[[Cmd], tuple[int, str]]


class Backend(Protocol):
    name: str

    def sync_plan(self, ips: list[str], prev_meta: dict[str, Any] | None, gen: str) -> SyncPlan: ...

    def teardown_plan(self, prev_meta: dict[str, Any] | None) -> list[Cmd]: ...


def clean_ips(ips: list[str]) -> list[str]:
    """Normalize and validate. Raises ValueError on anything that is not a plain IP (blocks command injection)."""
    out: list[str] = []
    seen: set[str] = set()
    for ip in ips:
        addr = ipaddress.ip_address(ip.strip())
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        s = str(addr)
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def split_versions(ips: list[str]) -> tuple[list[str], list[str]]:
    v4 = [i for i in ips if ipaddress.ip_address(i).version == 4]
    v6 = [i for i in ips if ipaddress.ip_address(i).version == 6]
    return v4, v6
