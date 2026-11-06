"""Plain IP lists for firewalls, CrowdSec import, spreadsheets. Protected addresses are always removed."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from typing import Any

from iisguard.firewall.safety import Protector

FORMATS = ("txt", "csv", "json", "nft")


def collect(blocks: list[dict[str, Any]], protector: Protector) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    keep: list[dict[str, Any]] = []
    dropped: list[dict[str, str]] = []
    seen: set[str] = set()
    for b in sorted(blocks, key=lambda b: -float(b.get("score", 0))):
        try:
            ip = str(ipaddress.ip_address(str(b["ip"]).strip()))
        except ValueError:
            dropped.append({"ip": str(b.get("ip")), "reason": "invalid-ip"})
            continue
        why = protector.reason(ip)
        if why:
            dropped.append({"ip": ip, "reason": why})
        elif ip not in seen:
            seen.add(ip)
            keep.append({"ip": ip, "score": b.get("score", 0), "rules": b.get("rules", [])})
    return keep, dropped


def render(rows: list[dict[str, Any]], fmt: str = "txt") -> str:
    if fmt == "txt":
        return "".join(r["ip"] + "\n" for r in rows)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["ip", "score", "rules"])
        for r in rows:
            w.writerow([r["ip"], r["score"], ";".join(r["rules"])])
        return buf.getvalue()
    if fmt == "json":
        return json.dumps(rows, indent=2)
    if fmt == "nft":
        v4 = [r["ip"] for r in rows if ":" not in r["ip"]]
        v6 = [r["ip"] for r in rows if ":" in r["ip"]]
        out = []
        if v4:
            out.append(f"add element inet filter blocked4 {{ {', '.join(v4)} }}")
        if v6:
            out.append(f"add element inet filter blocked6 {{ {', '.join(v6)} }}")
        return "\n".join(out) + ("\n" if out else "")
    raise ValueError(f"format must be one of {FORMATS}")
