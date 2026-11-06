"""Block-list state, safety filtering, capping, atomic sync, unban and rollback.

Dry-run by default: nothing is executed and no state is written unless ``live=True``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iisguard.firewall.base import Backend, Cmd, Runner, SyncPlan, clean_ips
from iisguard.firewall.safety import Protector
from iisguard.state import new_id, read_json, write_json

HISTORY_KEEP = 5


class FirewallError(RuntimeError):
    pass


def choose_backend(name: str = "auto", zone_id: str | None = None) -> Backend:
    from iisguard.firewall.cloudflare_api import CloudflareBackend
    from iisguard.firewall.linux_iptables import IptablesBackend
    from iisguard.firewall.linux_nftables import NftBackend
    from iisguard.firewall.windows_netsh import NetshBackend

    if name == "auto":
        name = "netsh" if sys.platform == "win32" else ("nftables" if shutil.which("nft") else "iptables")
    table: dict[str, Callable[[], Backend]] = {
        "netsh": NetshBackend, "nftables": NftBackend, "iptables": IptablesBackend,
        "cloudflare": lambda: CloudflareBackend(zone_id),
    }  # fmt: skip
    if name not in table:
        raise ValueError(f"unknown backend {name!r}; choose from {', '.join(table)}")
    return table[name]()


def default_runner(cmd: Cmd) -> tuple[int, str]:
    """Executes a command WITHOUT a shell. Only ever reached with --live."""
    if cmd.kind == "http":
        token = os.environ.get(cmd.secret_env, "")
        if not token:
            return 1, f"environment variable {cmd.secret_env} is not set"
        method, url = cmd.argv[0], cmd.argv[1]
        req = urllib.request.Request(
            url, data=cmd.stdin.encode() if cmd.stdin else None, method=method,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )  # fmt: skip
        try:
            with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - fixed https API host
                return 0, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return 1, f"HTTP {e.code}"
        except (urllib.error.URLError, OSError) as e:
            return 1, str(e)
    try:
        r = subprocess.run(cmd.argv, input=cmd.stdin, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)
    return r.returncode, (r.stdout + r.stderr).strip()


@dataclass
class SyncResult:
    live: bool
    ips: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    protected: list[dict[str, Any]] = field(default_factory=list)
    evicted: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class BlockManager:
    def __init__(
        self,
        backend: Backend,
        protector: Callable[[], Protector],
        state_file: Path,
        max_blocks: int = 500,
        ttl: int = 86400,
        runner: Runner = default_runner,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.backend, self.protector, self.state_file = backend, protector, state_file
        self.max_blocks, self.ttl, self.runner, self.clock = max_blocks, ttl, runner, clock

    # ------------------------------------------------------------------ state
    def state(self) -> dict[str, Any]:
        st = read_json(self.state_file, {})
        st.setdefault("entries", {})
        st.setdefault("history", [])
        st.setdefault("meta", {})
        return st  # type: ignore[no-any-return]

    def entries_list(self) -> list[dict[str, Any]]:
        now = self.clock()
        return sorted(
            ({"ip": ip, **e, "expired": e.get("expires", 0) < now} for ip, e in self.state()["entries"].items()),
            key=lambda e: -e.get("score", 0),
        )

    # ------------------------------------------------------------------ operations
    def sync(self, new_blocks: list[dict[str, Any]], live: bool = False) -> SyncResult:
        st = self.state()
        now = self.clock()
        prot = self.protector()
        res = SyncResult(live)
        merged: dict[str, dict[str, Any]] = {}
        for ip, e in st["entries"].items():
            if e.get("expires", 0) < now:
                continue
            why = prot.reason(ip)
            if why:  # state was edited or the admin moved: never keep a protected IP
                res.protected.append({"ip": ip, "reason": why})
                continue
            merged[ip] = e
        for b in new_blocks:
            ip = clean_ips([b["ip"]])[0]
            why = prot.reason(ip)
            if why:
                res.protected.append({"ip": ip, "reason": why})
                continue
            old = merged.get(ip, {})
            merged[ip] = {"score": max(float(b.get("score", 0)), old.get("score", 0)), "added": old.get("added", now),
                          "expires": now + self.ttl, "rules": sorted(set(old.get("rules", [])) | set(b.get("rules", [])))}  # fmt: skip
        ranked = sorted(merged.items(), key=lambda kv: -kv[1]["score"])
        res.evicted = [ip for ip, _ in ranked[self.max_blocks :]]
        merged = dict(ranked[: self.max_blocks])
        return self._apply(st, merged, live, res, push_history=True)

    def unban(self, ips: list[str], live: bool = False) -> SyncResult:
        st = self.state()
        drop = set(clean_ips(ips))
        merged = {ip: e for ip, e in st["entries"].items() if ip not in drop}
        return self._apply(st, merged, live, SyncResult(live), push_history=True)

    def rollback(self, live: bool = False) -> SyncResult:
        st = self.state()
        if not st["history"]:
            raise FirewallError("no previous generation to roll back to")
        prev = st["history"][-1]
        merged = {ip: dict(e) for ip, e in prev["entries"].items()}
        res = self._apply(st, merged, live, SyncResult(live), push_history=False)
        if live:
            st2 = self.state()
            st2["history"] = st2["history"][:-1]
            write_json(self.state_file, st2)
        return res

    def clear(self, live: bool = False) -> SyncResult:
        return self._apply(self.state(), {}, live, SyncResult(live), push_history=True)

    # ------------------------------------------------------------------ core
    def _apply(
        self, st: dict[str, Any], desired: dict[str, dict[str, Any]], live: bool, res: SyncResult, push_history: bool
    ) -> SyncResult:
        ips = list(desired)
        res.ips = ips
        res.added = sorted(set(ips) - set(st["entries"]))
        res.removed = sorted(set(st["entries"]) - set(ips))
        gen = new_id()
        plan: SyncPlan
        if ips:
            plan = self.backend.sync_plan(ips, st["meta"] or None, gen)
        else:
            plan = SyncPlan(cleanup=self.backend.teardown_plan(st["meta"] or None), meta={})
        res.commands = [c.display() for c in plan.add] + [f"(then) {c.display()}" for c in plan.cleanup]
        if not live:
            return res
        meta = dict(plan.meta)
        for cmd in plan.add:
            rc, out = self.runner(cmd)
            if rc != 0:
                for undo in plan.undo:
                    self.runner(undo)
                raise FirewallError(
                    f"{cmd.purpose or cmd.argv[0]} failed (rc={rc}): {out[:300]}; previous rules left in place"
                )
            if cmd.tag and cmd.kind == "http":
                try:
                    meta.setdefault("rule_ids", {})[cmd.tag] = json.loads(out)["result"]["id"]
                except (ValueError, KeyError, TypeError):
                    res.warnings.append(f"could not read rule id for {cmd.tag}")
        for cmd in plan.cleanup:
            rc, out = self.runner(cmd)
            if rc != 0:
                res.warnings.append(f"cleanup '{cmd.purpose or cmd.argv[0]}' failed (rc={rc}): {out[:200]}")
        if push_history:
            st["history"] = (st["history"] + [{"ts": self.clock(), "entries": st["entries"]}])[-HISTORY_KEEP:]
        st.update(backend=self.backend.name, meta=meta, entries=desired, updated=self.clock())
        write_json(self.state_file, st)
        return res
