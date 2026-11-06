"""Linux iptables/ip6tables. New chain per generation, filled via iptables-restore (atomic), then swapped in."""

from __future__ import annotations

from typing import Any

from iisguard.firewall.base import Cmd, SyncPlan, clean_ips, split_versions


def _restore_script(chain: str, ips: list[str]) -> str:
    rules = "".join(f"-A {chain} -s {ip} -j DROP\n" for ip in ips)
    return f"*filter\n:{chain} - [0:0]\n{rules}COMMIT\n"


class IptablesBackend:
    name = "iptables"

    def sync_plan(self, ips: list[str], prev_meta: dict[str, Any] | None, gen: str) -> SyncPlan:
        v4, v6 = split_versions(clean_ips(ips))
        tag = gen.replace("-", "").replace("T", "")[:14]
        chain = f"IISGUARD_{tag}"
        plan = SyncPlan(meta={"backend": self.name, "chain": chain})
        for tool, addrs in (("iptables", v4), ("ip6tables", v6)):
            restore = f"{tool}-restore"
            plan.add += [
                Cmd([restore, "--noflush"], stdin=_restore_script(chain, addrs), purpose=f"create {chain} with {len(addrs)} {tool} IP(s)"),
                Cmd([tool, "-I", "INPUT", "1", "-j", chain], purpose=f"activate {chain}"),
            ]  # fmt: skip
            plan.undo += [Cmd([tool, "-D", "INPUT", "-j", chain]), Cmd([tool, "-F", chain]), Cmd([tool, "-X", chain])]
            plan.cleanup += self._remove((prev_meta or {}).get("chain"), tool)
        return plan

    @staticmethod
    def _remove(chain: str | None, tool: str) -> list[Cmd]:
        if not chain:
            return []
        return [
            Cmd([tool, "-D", "INPUT", "-j", chain], purpose=f"deactivate old {chain}"),
            Cmd([tool, "-F", chain]),
            Cmd([tool, "-X", chain], purpose=f"delete old {chain}"),
        ]

    def teardown_plan(self, prev_meta: dict[str, Any] | None) -> list[Cmd]:
        chain = (prev_meta or {}).get("chain")
        return self._remove(chain, "iptables") + self._remove(chain, "ip6tables")
