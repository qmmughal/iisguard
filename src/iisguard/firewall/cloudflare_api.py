"""Optional Cloudflare IP Access Rules backend. Token comes from the environment (CLOUDFLARE_API_TOKEN), never a file.

Needs CLOUDFLARE_ZONE_ID too. Only used when you choose --backend cloudflare AND pass --live. The API shape follows
Cloudflare's documented zone IP Access Rules endpoint; it has not been exercised against a live account by the author.
"""

from __future__ import annotations

import json
import os
from typing import Any

from iisguard.firewall.base import Cmd, SyncPlan, clean_ips

API = "https://api.cloudflare.com/client/v4"
TOKEN_ENV = "CLOUDFLARE_API_TOKEN"  # noqa: S105 - name of the variable, not a secret


class CloudflareBackend:
    name = "cloudflare"

    def __init__(self, zone_id: str | None = None) -> None:
        self.zone = zone_id or os.environ.get("CLOUDFLARE_ZONE_ID", "")

    def _base(self) -> str:
        if not self.zone.isalnum():
            raise ValueError("set CLOUDFLARE_ZONE_ID (letters/digits only)")
        return f"{API}/zones/{self.zone}/firewall/access_rules/rules"

    def sync_plan(self, ips: list[str], prev_meta: dict[str, Any] | None, gen: str) -> SyncPlan:
        want = set(clean_ips(ips))
        have: dict[str, str] = dict((prev_meta or {}).get("rule_ids", {}))
        plan = SyncPlan(meta={"backend": self.name, "rule_ids": {k: v for k, v in have.items() if k in want}})
        for ip in sorted(want - set(have)):  # add first...
            body = {
                "mode": "block",
                "configuration": {"target": "ip6" if ":" in ip else "ip", "value": ip},
                "notes": "iisguard",
            }
            plan.add.append(Cmd(["POST", self._base()], json.dumps(body), f"block {ip}", "http", TOKEN_ENV, ip))
        for ip, rid in sorted(have.items()):  # ...then remove stale
            if ip not in want:
                plan.cleanup.append(Cmd(["DELETE", f"{self._base()}/{rid}"], None, f"unblock {ip}", "http", TOKEN_ENV))
        return plan

    def teardown_plan(self, prev_meta: dict[str, Any] | None) -> list[Cmd]:
        return [
            Cmd(["DELETE", f"{self._base()}/{rid}"], None, f"unblock {ip}", "http", TOKEN_ENV)
            for ip, rid in sorted((prev_meta or {}).get("rule_ids", {}).items())
        ]
