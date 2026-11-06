"""The single choke point deciding whether an IP may ever be blocked.

Every firewall backend and every block-candidate list must go through
:class:`Protector`. An IP is protected when it is: invalid, the admin's current
RDP/SSH session, one of the server's own addresses, allowlisted, inside a CDN /
load-balancer range, or not a globally routable address (private, loopback,
link-local, CGNAT, documentation, multicast...).
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping
from importlib import resources

from iisguard.config import Config

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Runner = Callable[[list[str]], str]


def _parse_net(text: str) -> IPNetwork:
    return ipaddress.ip_network(text.strip(), strict=False)


def _norm_ip(text: str) -> IPAddress | None:
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def bundled_cdn_ranges() -> dict[str, list[str]]:
    """Shipped CDN ranges, keyed by provider. Refreshed by ``update-rules``."""
    text = resources.files("iisguard").joinpath("data/cdn_ranges.json").read_text(encoding="utf-8")
    data = json.loads(text)
    out = {k: list(v) for k, v in data.get("providers", {}).items()}
    from iisguard.state import read_json, state_dir

    updated = read_json(state_dir() / "cdn_ranges.json", {})
    for k, v in updated.get("providers", {}).items():
        if isinstance(v, list) and v:
            out[str(k)] = [str(x) for x in v]  # a refreshed list replaces the bundled snapshot
    return out


class Protector:
    def __init__(
        self,
        allowlist: Iterable[str] = (),
        cdn_ranges: Iterable[str] = (),
        admin_ips: Iterable[str] = (),
        self_ips: Iterable[str] = (),
        protect_private: bool = True,
    ) -> None:
        self.allow_nets = [_parse_net(x) for x in allowlist]
        self.cdn_nets = [_parse_net(x) for x in cdn_ranges]
        self.admin = {a for a in (_norm_ip(x) for x in admin_ips) if a}
        self.self_ips = {a for a in (_norm_ip(x) for x in self_ips) if a}
        self.protect_private = protect_private

    def reason(self, ip: str) -> str | None:
        """Return why *ip* must not be blocked, or None if it may be."""
        addr = _norm_ip(ip)
        if addr is None:
            return "invalid-ip"
        if addr in self.admin:
            return "admin-session"
        if addr in self.self_ips:
            return "server-own-ip"
        for net in self.allow_nets:
            if addr.version == net.version and addr in net:
                return "allowlisted"
        for net in self.cdn_nets:
            if addr.version == net.version and addr in net:
                return "cdn-or-load-balancer"
        if self.protect_private and not addr.is_global:
            return "non-public-address"
        return None


def _run(cmd: list[str]) -> str:
    # Read-only inspection commands only (netstat / ss).
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _split_endpoint(endpoint: str) -> tuple[str, str]:
    """'1.2.3.4:5' -> ('1.2.3.4', '5');  '[::1]:5' -> ('::1', '5');  'fe80::1:22' -> ('fe80::1', '22')."""
    ep = endpoint.strip()
    if ep.startswith("["):
        host, _, port = ep[1:].partition("]")
        return host, port.lstrip(":")
    host, _, port = ep.rpartition(":")
    return host, port


def detect_admin_ips(
    env: Mapping[str, str] | None = None,
    runner: Runner | None = None,
    platform: str | None = None,
    admin_ports: tuple[int, ...] = (22, 3389),
) -> set[str]:
    """Find the IPs of administrators connected right now (SSH / RDP). Read-only."""
    env = os.environ if env is None else env
    run = runner or _run
    plat = platform or sys.platform
    found: set[str] = set()
    for var in ("SSH_CONNECTION", "SSH_CLIENT"):
        parts = env.get(var, "").split()
        if parts and _norm_ip(parts[0]):
            found.add(parts[0])
    if plat.startswith("win"):
        out = run(["netstat", "-n", "-p", "tcp"]) + run(["netstat", "-n", "-p", "tcpv6"])
        for line in out.splitlines():
            cols = line.split()
            if len(cols) >= 4 and cols[0].upper() == "TCP" and cols[-1].upper().startswith("ESTAB"):
                _, lport = _split_endpoint(cols[1])
                rhost, _ = _split_endpoint(cols[2])
                if lport.isdigit() and int(lport) in admin_ports and _norm_ip(rhost):
                    found.add(rhost)
    elif shutil.which("ss") or runner:
        for line in run(["ss", "-Htn", "state", "established"]).splitlines():
            cols = line.split()
            if len(cols) >= 4:
                _, lport = _split_endpoint(cols[-2])
                rhost, _ = _split_endpoint(cols[-1])
                if lport.isdigit() and int(lport) in admin_ports and _norm_ip(rhost):
                    found.add(rhost)
    return found


def detect_self_ips() -> set[str]:
    ips: set[str] = {"127.0.0.1", "::1"}
    try:
        host = socket.gethostname()
        ips.update(socket.gethostbyname_ex(host)[2])
        for info in socket.getaddrinfo(host, None):
            ips.add(str(info[4][0]).split("%")[0])
    except OSError:
        pass
    return ips


def build_protector(cfg: Config, extra_admin_ips: Iterable[str] = (), detect: bool | None = None) -> Protector:
    do_detect = cfg.detect_admin if detect is None else detect
    admin = set(cfg.admin_ips) | set(extra_admin_ips)
    self_ips = set(cfg.self_ips)
    if do_detect:
        admin |= detect_admin_ips()
        self_ips |= detect_self_ips()
    cdn = list(cfg.cdn_ranges)
    for ranges in bundled_cdn_ranges().values():
        cdn.extend(ranges)
    return Protector(cfg.allowlist, cdn, admin, self_ips, cfg.protect_private)
