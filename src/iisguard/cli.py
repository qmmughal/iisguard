"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

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
    "exposure": ("M5", "read-only external exposure check: exposure --url <your domain>"),
    "export": ("M5", "export rules: sigma | yara | crowdsec | modsec | iplist"),
    "report": ("M5", "generate csv / json / html / sarif reports"),
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

    hu = sub.add_parser("hunt", help="hunt web-shells, exposed secrets, risky web.config, web-server child processes")
    hu.add_argument("paths", nargs="*", help="webroot folder(s) to search")
    hu.add_argument(
        "--checks",
        default="files,secrets,webconfig",
        help="comma list of: files,secrets,webconfig,processes (default: files,secrets,webconfig)",
    )
    hu.add_argument("--since", type=float, metavar="DAYS", help="treat files changed in the last DAYS as recent")
    hu.add_argument("--min-score", type=int, default=40, help="minimum file score to report (default 40)")
    hu.add_argument(
        "--events", action="append", default=[], metavar="FILE", help="exported 4688/Sysmon XML or auditd log"
    )
    hu.add_argument("--url", help="base URL to test whether exposed files are reachable (needs --confirm-owner)")
    hu.add_argument("--confirm-owner", help="the host name you own; the URL check refuses any other host")
    hu.add_argument("--verbose", action="store_true", help="include low-severity findings")
    hu.add_argument("--output-format", choices=("text", "json"), default="text")
    hu.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if a finding of this severity or higher exists")

    fi = sub.add_parser("fim", help="file-integrity monitoring: fim init | fim check")
    fsub = fi.add_subparsers(dest="fim_cmd", metavar="<init|check>", required=True)
    for nm, hp in (("init", "record a baseline of the webroot"), ("check", "compare the webroot with the baseline")):
        fp = fsub.add_parser(nm, help=hp)
        fp.add_argument("path", help="webroot folder")
        fp.add_argument("--baseline", default="iisguard-fim.json", help="baseline file (keep a copy off-server)")
        if nm == "init":
            fp.add_argument("--all", action="store_true", help="hash every file, not only scripts/config/js/html")
        else:
            fp.add_argument("--output-format", choices=("text", "json"), default="text")
            fp.add_argument("--fail-on-change", action="store_true", help="exit 1 if anything changed")

    from iisguard import cli_m4

    cli_m4.register(sub)

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


def _cmd_hunt(a: argparse.Namespace) -> int:
    import json
    import subprocess

    from iisguard import process, webshell
    from iisguard.audit import secrets, webconfig

    checks = {c.strip() for c in a.checks.split(",") if c.strip()}
    bad = checks - {"files", "secrets", "webconfig", "processes"}
    if bad:
        print(f"error: unknown check(s): {', '.join(sorted(bad))}", file=sys.stderr)
        return 2
    if checks & {"files", "secrets", "webconfig"} and not a.paths:
        print("error: give at least one webroot path", file=sys.stderr)
        return 2
    result: dict[str, object] = {}
    worst = -1
    if "files" in checks:
        fs = webshell.hunt(a.paths, a.since, a.min_score)
        result["files"] = [f.to_dict() for f in fs]
        worst = max([worst, *(SEVERITY_RANK[f.severity] for f in fs)])
    if "secrets" in checks:
        ss = secrets.scan_webroot(a.paths, include_low=a.verbose)
        if a.url:
            if not a.confirm_owner:
                print("error: --url needs --confirm-owner <host you own>", file=sys.stderr)
                return 2
            try:
                secrets.check_reachable(ss, a.url, a.confirm_owner)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
        result["secrets"] = [f.to_dict() for f in ss]
        worst = max([worst, *(SEVERITY_RANK[f.severity] for f in ss)])
    if "webconfig" in checks:
        ca = webconfig.audit_roots(a.paths)
        shown = [f for f in ca.findings if a.verbose or f.severity != "low"]
        result["webconfig"] = {"files": ca.files, "findings": [f.to_dict() for f in shown], "skipped": ca.skipped}
        worst = max([worst, *(SEVERITY_RANK[f.severity] for f in shown)])
    if "processes" in checks or a.events:
        events: list[process.ProcEvent] = []
        for ev_file in a.events:
            try:
                text = Path(ev_file).read_text(encoding="utf-8-sig", errors="replace")
                events += (
                    process.parse_auditd(text.splitlines()) if "type=SYSCALL" in text else process.parse_event_xml(text)
                )
            except (OSError, ValueError) as e:
                print(f"error: {ev_file}: {e}", file=sys.stderr)
                return 2
        if "processes" in checks:

            def run(cmd: list[str]) -> str:
                return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False).stdout

            events += process.live_events(run)
        pf = process.detect(events)
        result["processes"] = {"examined": len(events), "findings": [f.to_dict() for f in pf]}
        worst = max([worst, *(SEVERITY_RANK[f.severity] for f in pf)])
    print(json.dumps(result, indent=2) if a.output_format == "json" else _format_hunt(result))
    return 1 if a.fail_on and worst >= SEVERITY_RANK[a.fail_on] else 0


def _format_hunt(result: dict[str, object]) -> str:
    out: list[str] = []
    files = result.get("files")
    if isinstance(files, list):
        out.append(f"Suspicious files: {len(files)}")
        for f in files:
            out.append(f"  [{f['severity']:<8}] score={f['score']:<3} {f['path']}")
            out += [f"      - {r}" for r in f["reasons"]]
            out.append(f"      sha256={f['sha256']}")
    secs = result.get("secrets")
    if isinstance(secs, list):
        out.append(f"\nSecrets / exposed files: {len(secs)} (values are masked)")
        for f in secs:
            reach = {True: "  REACHABLE OVER HTTP", False: "  not reachable", None: ""}[f["reachable"]]
            loc = f":{f['line']}" if f["line"] else ""
            out.append(f"  [{f['severity']:<8}] {f['path']}{loc}: {f['detail']}{reach}")
    wc = result.get("webconfig")
    if isinstance(wc, dict):
        out.append(f"\nweb.config audit: {wc['files']} file(s), {len(wc['findings'])} finding(s)")
        for f in wc["findings"]:
            fp = f" key={f['key_fingerprint']}" if f["key_fingerprint"] else ""
            out.append(f"  [{f['severity']:<8}] {f['path']}: {f['id']}{fp}: {f['detail']}")
            if f["fix"]:
                out.append(f"      fix: {f['fix']}")
        out += [f"  skipped {sk}" for sk in wc["skipped"]]
    pr = result.get("processes")
    if isinstance(pr, dict):
        out.append(f"\nProcess check: {pr['examined']} process record(s), {len(pr['findings'])} finding(s)")
        for f in pr["findings"]:
            out.append(f"  [{f['severity']:<8}] {f['rule']}: {f['parent']} -> {f['child']}  {f['cmdline'][:100]}")
    return "\n".join(out)


def _cmd_fim(a: argparse.Namespace) -> int:
    import json

    from iisguard import fim

    try:
        if a.fim_cmd == "init":
            n = fim.init_baseline(a.path, a.baseline, a.all)
            print(f"Baseline written to {a.baseline}: {n} file(s). Keep a copy somewhere the web server cannot write.")
            return 0
        res = fim.check_baseline(a.path, a.baseline)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.output_format == "json":
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(f"Added {len(res.added)}, modified {len(res.modified)}, deleted {len(res.deleted)}")
        for x in res.added:
            print(f"  + {x['path']}" + ("   <-- script in an upload/media folder" if x["suspicious"] else ""))
        for x in res.modified:
            print(f"  ~ {x['path']}")
        for gone in res.deleted:
            print(f"  - {gone}")
    return 1 if a.fail_on_change and res.changed else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if getattr(args, "func", None) is not None:
        return int(args.func(args))
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "audit":
        return _cmd_audit(args)
    if args.command == "hunt":
        return _cmd_hunt(args)
    if args.command == "fim":
        return _cmd_fim(args)
    ms = PLANNED[args.command][0]
    print(f"iisguard {args.command}: not implemented yet (planned for {ms}).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
