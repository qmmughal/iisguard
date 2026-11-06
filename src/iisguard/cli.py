"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from iisguard import __version__
from iisguard.analyzer import Analyzer, Report
from iisguard.config import ConfigError, load_config
from iisguard.firewall.safety import build_protector
from iisguard.logs import FORMATS, UnknownFormat, iter_events
from iisguard.models import SEVERITIES, SEVERITY_RANK, ParseStats
from iisguard.report import render_json, render_text
from iisguard.rules import RuleError, RuleSet, load_rules

# command -> (milestone that implements it, help text)
PLANNED: dict[str, tuple[str, str]] = {
    "watch": ("M4", "tail logs and block attackers (dry-run unless --live)"),
    "fim": ("M3", "file-integrity baseline: fim init | fim check"),
    "hunt": ("M3", "hunt for web-shells and suspicious files in a webroot"),
    "exposure": ("M5", "read-only external exposure check: exposure --url <your domain>"),
    "block": ("M4", "block list | unban | rollback"),
    "fix": ("M4", "guided fixes: machinekey | headers | uploads | php-ini | wp-upgrade-dir [--apply]"),
    "quarantine": ("M4", "move a suspicious file to quarantine"),
    "export": ("M5", "export rules: sigma | yara | crowdsec | modsec | iplist"),
    "report": ("M5", "generate csv / json / html / sarif reports"),
    "service": ("M4", "service install | uninstall | start | stop"),
    "update-rules": ("M5", "fetch the latest rule pack"),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iisguard",
        description="Audit, detect, block, fix and share detections for web servers (IIS, nginx, Apache, PHP).",
        epilog="Everything is read-only / dry-run by default.",
    )
    p.add_argument("--version", action="version", version=f"iisguard {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    sc = sub.add_parser("scan", help="analyze log files for attacks (read-only)")
    sc.add_argument("paths", nargs="+", help="log files ('-' for stdin, .gz supported)")
    sc.add_argument("--format", default="auto", choices=FORMATS, help="log format (default: auto-detect)")
    sc.add_argument("--config", help="config file (default: ./iisguard.json or .yaml)")
    sc.add_argument("--rules", help="rules.yaml to use instead of the bundled pack")
    sc.add_argument("--output-format", choices=("text", "json"), default="text")
    sc.add_argument("--top", type=int, default=30, help="rows to show per section in text output")
    sc.add_argument("--block-score", type=int, help="override the block threshold")
    sc.add_argument("--admin-ip", action="append", default=[], help="IP that must never be blocked (repeatable)")
    sc.add_argument("--no-detect-admin", action="store_true", help="skip auto-detection of your RDP/SSH session")
    sc.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if a finding of this severity or higher exists")

    au = sub.add_parser("audit", help="audit installed software against CISA KEV and known fixed versions")
    au.add_argument("--kev", action="store_true", help="also match CISA KEV (downloads the feed unless --offline)")
    au.add_argument("--offline", action="store_true", help="no network: use cache or bundled KEV snapshot")
    au.add_argument("--inventory", help="JSON inventory file instead of scanning this machine")
    au.add_argument("--webroot", action="append", default=[], help="folder to search for WordPress (repeatable)")
    au.add_argument("--app-root", action="append", default=[], help="folder to search for self-contained .NET apps")
    au.add_argument("--php-dir", action="append", default=[], help="extra folder to search for php binaries")
    au.add_argument("--output-format", choices=("table", "json"), default="table")
    au.add_argument("--all", action="store_true", help="also show items that are already fixed")
    au.add_argument("--cache-dir", help="where the KEV feed is cached")
    au.add_argument("--fail-on-vulnerable", action="store_true", help="exit 1 on vulnerable/EOL/misconfigured")

    for name, (ms, text) in PLANNED.items():
        sub.add_parser(name, help=f"{text} [planned {ms}]", add_help=True).add_argument(
            "args", nargs="*", help=argparse.SUPPRESS
        )
    return p


def _cmd_scan(a: argparse.Namespace) -> int:
    try:
        cfg = load_config(a.config)
        if a.block_score:
            cfg.block_score = a.block_score
        rules = load_rules(a.rules or cfg.rules_path or None, cfg.disabled_rules)
    except (ConfigError, RuleError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for w in cfg.warnings:
        print(f"warning: {w}", file=sys.stderr)
    protector = build_protector(cfg, a.admin_ip, detect=False if a.no_detect_admin else None)
    an = Analyzer(RuleSet(rules), cfg, protector)
    stats = ParseStats()
    try:
        for path in a.paths:
            for ev in iter_events(path, a.format, stats):
                an.feed(ev)
    except (UnknownFormat, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    rep: Report = an.finish()
    rep.stats.update(files=len(a.paths), bad_lines=stats.bad, lines=stats.lines, formats=stats.formats)
    print(render_json(rep) if a.output_format == "json" else render_text(rep, a.top))
    if a.fail_on and (rep.hits or rep.host_findings) and SEVERITY_RANK[rep.max_severity] >= SEVERITY_RANK[a.fail_on]:
        return 1
    return 0


def _cmd_audit(a: argparse.Namespace) -> int:
    import json
    from pathlib import Path

    from iisguard.audit.collect import collect_all
    from iisguard.audit.engine import Auditor, render_table
    from iisguard.audit.inventory import load_inventory
    from iisguard.audit.kev import load_kev

    try:
        items = load_inventory(a.inventory) if a.inventory else collect_all(a.webroot, a.app_root, a.php_dir)
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    kev = load_kev(offline=a.offline, cache_dir=Path(a.cache_dir) if a.cache_dir else None) if a.kev else None
    auditor = Auditor(kev)
    findings = auditor.run(items)
    watch = auditor.kev_watch(items) if kev else []
    if a.output_format == "json":
        print(json.dumps({"kev": {"source": kev.source, "catalog": kev.catalog_version} if kev else None,
                          "inventory": len(items), "findings": [f.to_dict() for f in findings],
                          "kev_watch": watch}, indent=2))  # fmt: skip
    else:
        kev_note = f" KEV catalog {kev.catalog_version} ({kev.source})." if kev else ""
        print(f"Inventory: {len(items)} item(s).{kev_note}")
        print(render_table(findings, a.all))
        if watch:
            print("\nRecent KEV entries (12 months) for products found here; no verified fixed-version rule:")
            for w in watch:
                print(f"  {w['cve']}  {w['product']:<14} found={w['found']:<24} due={w['kev_due']}  {w['name']}")
    bad = {"vulnerable", "eol", "config"}
    return 1 if a.fail_on_vulnerable and any(f.status in bad for f in findings) else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "audit":
        return _cmd_audit(args)
    ms = PLANNED[args.command][0]
    print(f"iisguard {args.command}: not implemented yet (planned for {ms}).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
