"""CLI: export, report, exposure, update-rules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from iisguard.config import ConfigError, load_config
from iisguard.export import crowdsec, iplist, modsec, sigma, yara
from iisguard.firewall.safety import build_protector
from iisguard.report import render as rr
from iisguard.report.model import from_document
from iisguard.rules import RuleError, load_rules
from iisguard.state import state_dir


def register(sub: Any) -> None:
    e = sub.add_parser("export", help="export detections: sigma | yara | crowdsec | modsec | iplist")
    e.add_argument("kind", choices=("sigma", "yara", "crowdsec", "modsec", "iplist"))
    e.add_argument("--out", help="output file (crowdsec: a folder). Default: stdout")
    e.add_argument("--rules", help="rules.yaml override")
    e.add_argument("--config")
    e.add_argument(
        "--min-score", type=int, default=10, help="skip rules scoring below this (default 10; crowdsec uses 40)"
    )
    e.add_argument(
        "--mode",
        choices=modsec.MODES,
        default="detect",
        help="modsec: detect (log), block (403) or crs (anomaly score)",
    )
    e.add_argument("--id-base", type=int, default=modsec.ID_BASE, help="modsec: first rule id")
    e.add_argument("--from", dest="source", help="iplist/crowdsec: scan JSON (blocks) or block-state file")
    e.add_argument("--format", dest="fmt", choices=iplist.FORMATS, default="txt", help="iplist format")
    e.add_argument("--admin-ip", action="append", default=[], help="never include this IP (repeatable)")
    e.add_argument("--no-detect-admin", action="store_true")
    e.set_defaults(func=cmd_export)

    r = sub.add_parser("report", help="turn scan/audit/hunt/exposure JSON into csv | json | html | sarif")
    r.add_argument("inputs", nargs="+", help="JSON files produced with --output-format json")
    r.add_argument("--format", choices=rr.FORMATS, default="html")
    r.add_argument("--out", help="output file (default: stdout)")
    r.set_defaults(func=cmd_report)

    x = sub.add_parser(
        "exposure", help="read-only external check of a site you own (headers, TLS, listings, panels, origin)"
    )
    x.add_argument("--url", required=True, help="https://your-domain.example")
    x.add_argument("--confirm-owner", required=True, help="the host name you own; any other host is refused")
    x.add_argument("--origin-ip", help="your origin server IP, to test whether it answers without the CDN")
    x.add_argument("--delay", type=float, default=0.5, help="seconds between requests (min 0.25)")
    x.add_argument("--output-format", choices=("text", "json"), default="text")
    x.set_defaults(func=cmd_exposure)

    u = sub.add_parser("update-rules", help="fetch the latest rule pack (and optionally CDN ranges)")
    u.add_argument("--check", action="store_true", help="only report whether an update exists")
    u.add_argument("--cdn", action="store_true", help="also refresh Cloudflare and CloudFront ranges")
    u.add_argument("--index-url", help="alternative pack index (https only)")
    u.add_argument("--state-dir")
    u.set_defaults(func=cmd_update)


def _blocks_from(source: str) -> list[dict[str, Any]]:
    data = json.loads(Path(source).read_text(encoding="utf-8-sig"))
    if isinstance(data, dict) and "blocks" in data:
        return list(data["blocks"])
    if isinstance(data, dict) and "entries" in data:
        return [
            {"ip": ip, "score": e.get("score", 0), "rules": e.get("rules", [])} for ip, e in data["entries"].items()
        ]
    raise ValueError("expected scan JSON (with 'blocks') or a block-state file")


def cmd_export(a: argparse.Namespace) -> int:
    try:
        cfg = load_config(a.config)
        rules = load_rules(a.rules or cfg.rules_path or None, cfg.disabled_rules)
        if a.kind == "sigma":
            text = sigma.export(rules, a.min_score)
        elif a.kind == "yara":
            text = yara.export()
        elif a.kind == "modsec":
            text = modsec.export(rules, a.mode, a.min_score, a.id_base)
        else:
            text = ""
            ips: list[str] = []
            dropped: list[dict[str, str]] = []
            if a.source:
                prot = build_protector(cfg, a.admin_ip, detect=False if a.no_detect_admin else None)
                rows, dropped = iplist.collect(_blocks_from(a.source), prot)
                ips = [r["ip"] for r in rows]
                if a.kind == "iplist":
                    text = iplist.render(rows, a.fmt)
            elif a.kind == "iplist":
                print("error: iplist needs --from scan.json (or a block-state file)", file=sys.stderr)
                return 2
            if dropped:
                print(f"note: {len(dropped)} protected/invalid address(es) were left out", file=sys.stderr)
            if a.kind == "crowdsec":
                scen, skipped = crowdsec.export(rules, cfg, max(a.min_score, 40))
                out = Path(a.out or "iisguard-crowdsec")
                out.mkdir(parents=True, exist_ok=True)
                (out / "iisguard-scenarios.yaml").write_text(scen, encoding="utf-8", newline="\n")
                (out / "iisguard-blocklist.txt").write_text(crowdsec.blocklist(ips), encoding="utf-8", newline="\n")
                print(f"wrote {out}/iisguard-scenarios.yaml and iisguard-blocklist.txt ({len(ips)} IPs)")
                if skipped:
                    print(f"note: skipped (RE2 has no lookaround): {', '.join(skipped)}", file=sys.stderr)
                return 0
        if a.out:
            Path(a.out).write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {a.out}")
        else:
            print(text, end="")
    except (ConfigError, RuleError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    findings = []
    try:
        for p in a.inputs:
            doc = json.loads(Path(p).read_text(encoding="utf-8-sig"))
            if not isinstance(doc, dict):
                raise ValueError(f"{p}: expected a JSON object from --output-format json")
            findings += from_document(doc)
        rr.write(findings, a.format, a.out)
    except (ValueError, OSError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.out:
        print(f"wrote {a.out} ({len(findings)} findings)")
    return 0


def cmd_exposure(a: argparse.Namespace) -> int:
    from iisguard import exposure

    try:
        findings, info = exposure.check(a.url, a.confirm_owner, a.origin_ip, delay=max(a.delay, 0.25))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.output_format == "json":
        print(
            json.dumps({"exposure": {"info": info, "findings": [f.to_dict() for f in findings]}}, indent=2, default=str)
        )
    else:
        print(
            f"Checked {info['host']} with {info['requests']} read-only request(s). IPs: {', '.join(info.get('ips', [])) or '-'}"
        )
        for f in findings:
            print(f"  [{f.severity:<8}] {f.title}" + (f"  -> {f.location}" if f.location != info["host"] else ""))
            if f.detail:
                print(f"      {f.detail}")
        if not findings:
            print("  nothing found")
    return 0


def cmd_update(a: argparse.Namespace) -> int:
    from iisguard import rules_update as ru

    st = state_dir(a.state_dir)
    try:
        for m in ru.update_rules(a.index_url or ru.INDEX_URL, state=st, check_only=a.check):
            print(m)
        if a.cdn and not a.check:
            for m in ru.update_cdn(state=st):
                print("cdn " + m)
    except (ru.UpdateError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0
