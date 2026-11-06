"""Windows Defender Firewall via netsh advfirewall. Rules are named iisguard-<generation>-<n> (<=200 IPs each)."""

from __future__ import annotations

from typing import Any

from iisguard.firewall.base import Cmd, SyncPlan, clean_ips

BATCH = 200
PREFIX = "iisguard"


class NetshBackend:
    name = "netsh"

    @staticmethod
    def _add(rule: str, ips: list[str]) -> Cmd:
        return Cmd(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule}",
                "dir=in",
                "action=block",
                "protocol=any",
                f"remoteip={','.join(ips)}",
                "enable=yes",
                "description=iisguard automatic block",
            ],  # fmt: skip
            purpose=f"block {len(ips)} IP(s)",
        )

    @staticmethod
    def _delete(rule: str) -> Cmd:
        return Cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"], purpose=f"remove {rule}")

    def sync_plan(self, ips: list[str], prev_meta: dict[str, Any] | None, gen: str) -> SyncPlan:
        ips = clean_ips(ips)
        names = [f"{PREFIX}-{gen}-{n + 1}" for n in range((len(ips) + BATCH - 1) // BATCH)]
        plan = SyncPlan(meta={"backend": self.name, "rules": names})
        for n, rule in enumerate(names):
            plan.add.append(self._add(rule, ips[n * BATCH : (n + 1) * BATCH]))
        plan.undo = [self._delete(r) for r in names]
        plan.cleanup = [self._delete(r) for r in (prev_meta or {}).get("rules", [])]
        return plan

    def teardown_plan(self, prev_meta: dict[str, Any] | None) -> list[Cmd]:
        return [self._delete(r) for r in (prev_meta or {}).get("rules", [])]
