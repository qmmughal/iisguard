"""Linux nftables. One `nft -f -` transaction replaces the whole set, so the swap is atomic by construction."""

from __future__ import annotations

from typing import Any

from iisguard.firewall.base import Cmd, SyncPlan, clean_ips, split_versions

TABLE = "iisguard"


class NftBackend:
    name = "nftables"

    def script(self, ips: list[str]) -> str:
        v4, v6 = split_versions(clean_ips(ips))
        lines = [
            f"table inet {TABLE} {{",
            "  set blocked4 { type ipv4_addr; }",
            "  set blocked6 { type ipv6_addr; }",
            "  chain input { type filter hook input priority -10; policy accept;",
            "    ip saddr @blocked4 drop",
            "    ip6 saddr @blocked6 drop",
            "  }",
            "}",
            f"flush set inet {TABLE} blocked4",
            f"flush set inet {TABLE} blocked6",
        ]
        if v4:
            lines.append(f"add element inet {TABLE} blocked4 {{ {', '.join(v4)} }}")
        if v6:
            lines.append(f"add element inet {TABLE} blocked6 {{ {', '.join(v6)} }}")
        return "\n".join(lines) + "\n"

    def sync_plan(self, ips: list[str], prev_meta: dict[str, Any] | None, gen: str) -> SyncPlan:
        plan = SyncPlan(meta={"backend": self.name, "table": TABLE})
        plan.add = [Cmd(["nft", "-f", "-"], stdin=self.script(ips), purpose=f"atomically load {len(ips)} IP(s)")]
        plan.undo = []  # the transaction either applies fully or not at all
        plan.cleanup = []
        return plan

    def teardown_plan(self, prev_meta: dict[str, Any] | None) -> list[Cmd]:
        return [Cmd(["nft", "delete", "table", "inet", TABLE], purpose="remove the iisguard table")]
