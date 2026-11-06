"""CLI: watch, block, fix, quarantine, service. Everything is dry-run unless --live (firewall) / --apply (files)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from iisguard.analyzer import Analyzer
from iisguard.config import ConfigError, load_config
from iisguard.firewall.manager import BlockManager, FirewallError, SyncResult, choose_backend, default_runner
from iisguard.firewall.safety import Protector, build_protector
from iisguard.fix import base as fixbase
from iisguard.logs import FORMATS, UnknownFormat, iter_events
from iisguard.models import ParseStats
from iisguard.rules import RuleError, RuleSet, load_rules
from iisguard.state import state_dir

BACKENDS = ("auto", "netsh", "nftables", "iptables", "cloudflare")


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", help="config file")
    p.add_argument("--backend", choices=BACKENDS, default="auto")
    p.add_argument("--state-dir", help="where block state, backups and quarantine are kept")
    p.add_argument("--admin-ip", action="append", default=[], help="IP that must never be blocked (repeatable)")
    p.add_argument("--no-detect-admin", action="store_true", help="skip auto-detection of your RDP/SSH session")
    p.add_argument("--ttl", type=int, default=86400, help="seconds a block lasts (default 24 h)")
    p.add_argument(
        "--live", action="store_true", help="actually change the firewall (default: dry-run, nothing changes)"
    )


def register(sub: Any) -> None:
    w = sub.add_parser("watch", help="tail logs and block attackers (dry-run unless --live)")
    w.add_argument("paths", nargs="+", help="log files to follow")
    w.add_argument("--format", default="auto", choices=FORMATS)
    w.add_argument("--rules", help="rules.yaml override")
    w.add_argument("--interval", type=float, default=30.0, help="seconds between block-list syncs")
    w.add_argument("--poll", type=float, default=2.0, help="seconds between log reads")
    w.add_argument("--from-start", action="store_true", help="process existing content instead of only new lines")
    w.add_argument("--max-steps", type=int, help=argparse.SUPPRESS)
    _common(w)
    w.set_defaults(func=cmd_watch)

    b = sub.add_parser("block", help="block list | sync | unban | rollback | clear")
    bs = b.add_subparsers(dest="block_cmd", metavar="<list|sync|unban|rollback|clear>", required=True)
    bl = bs.add_parser("list", help="show the current block list")
    bl.add_argument("--state-dir")
    bl.add_argument("--json", action="store_true")
    bsync = bs.add_parser("sync", help="scan logs once and sync the block list")
    bsync.add_argument("paths", nargs="+")
    bsync.add_argument("--format", default="auto", choices=FORMATS)
    bsync.add_argument("--rules")
    _common(bsync)
    bun = bs.add_parser("unban", help="remove IPs from the block list")
    bun.add_argument("ips", nargs="+")
    _common(bun)
    brb = bs.add_parser("rollback", help="restore the previous block list")
    _common(brb)
    bcl = bs.add_parser("clear", help="remove every iisguard firewall rule")
    _common(bcl)
    b.set_defaults(func=cmd_block)

    f = sub.add_parser("fix", help="guided fixes (dry-run by default; --apply to change files)")
    fs = f.add_subparsers(dest="fix_cmd", metavar="<fix>", required=True)

    def fx(name: str, help_: str) -> argparse.ArgumentParser:
        p: argparse.ArgumentParser = fs.add_parser(name, help=help_)
        p.add_argument("--apply", action="store_true", help="write the changes (a backup is made first)")
        p.add_argument("--state-dir")
        return p

    mk = fx("machinekey", "replace shared (or all hard-coded) machineKeys with unique random keys")
    mk.add_argument("paths", nargs="+")
    mk.add_argument("--all-hardcoded", action="store_true")
    hd = fx("headers", "add security headers to an IIS web.config (nginx/Apache snippets printed)")
    hd.add_argument("path", help="web.config or its folder")
    hd.add_argument("--hsts", action="store_true")
    up = fx("uploads", "deny script execution in upload folders")
    up.add_argument("dirs", nargs="+")
    up.add_argument("--server", choices=("iis", "apache"), default="iis")
    up.add_argument(
        "--handlers", action="store_true", help="IIS: also set handlers accessPolicy=Read (needs delegation)"
    )
    pi = fx("php-ini", "temporary php.ini hardening: session.upload_progress.enabled=0")
    pi.add_argument("--ini", help="php.ini path (default: ask `php --ini`)")
    pi.add_argument("--post-max-size", help="also set post_max_size, e.g. 32M")
    wp = fx("wp-upgrade-dir", "deny web access to wp-content/upgrade and setup-config.php")
    wp.add_argument("wp_root")
    rb = fs.add_parser("rollback", help="restore the files changed by a fix")
    rb.add_argument("--id", help="backup id (default: the latest)")
    rb.add_argument("--force", action="store_true")
    rb.add_argument("--state-dir")
    ls = fs.add_parser("list", help="list fix backups")
    ls.add_argument("--state-dir")
    f.set_defaults(func=cmd_fix)

    q = sub.add_parser("quarantine", help="move a suspicious file out of the web tree (dry-run unless --apply)")
    q.add_argument("file", nargs="?")
    q.add_argument("--apply", action="store_true")
    q.add_argument("--list", action="store_true")
    q.add_argument("--restore", metavar="ID")
    q.add_argument("--force", action="store_true")
    q.add_argument("--reason", default="")
    q.add_argument("--state-dir")
    q.set_defaults(func=cmd_quarantine)

    s = sub.add_parser(
        "service", help="install | uninstall | start | stop the watcher as a service (dry-run unless --apply)"
    )
    s.add_argument("action", choices=("install", "uninstall", "start", "stop"))
    s.add_argument("--logs", nargs="+", default=[], help="log files for `install`")
    s.add_argument("--backend", choices=BACKENDS, default="auto")
    s.add_argument("--config")
    s.add_argument("--live", action="store_true", help="make the installed service enforce (default: dry-run service)")
    s.add_argument("--apply", action="store_true", help="really install/start (writes files, runs schtasks/systemctl)")
    s.add_argument("--write-dir", help="only write the generated files here and print the commands")
    s.set_defaults(func=cmd_service)


# ------------------------------------------------------------------ helpers
def _manager(a: argparse.Namespace, cfg_max: int, backend_name: str | None = None) -> tuple[BlockManager, Any]:
    cfg = load_config(a.config)
    cfg.max_blocks = cfg_max or cfg.max_blocks

    def prot() -> Any:
        return build_protector(cfg, a.admin_ip, detect=False if a.no_detect_admin else None)

    mgr = BlockManager(
        choose_backend(backend_name or a.backend), prot, state_dir(a.state_dir) / "blocks.json",
        max_blocks=cfg.max_blocks, ttl=a.ttl, runner=default_runner,
    )  # fmt: skip
    return mgr, cfg


def _show(res: SyncResult) -> None:
    mode = "LIVE: firewall changed" if res.live else "DRY-RUN: nothing was changed (add --live to apply)"
    print(f"{mode}\n  block list now: {len(res.ips)} IP(s); +{len(res.added)} new, -{len(res.removed)} removed")
    for p in res.protected:
        print(f"  protected (never blocked): {p['ip']}  reason={p['reason']}")
    if res.evicted:
        print(f"  over the cap, lowest scores dropped: {len(res.evicted)}")
    if res.added:
        print("  new: " + ", ".join(res.added[:20]) + (" ..." if len(res.added) > 20 else ""))
    if res.commands and not res.live:
        print("  commands that would run:")
        for c in res.commands[:12]:
            print(f"    {c}")
    for w in res.warnings:
        print(f"  warning: {w}")


def _scan_blocks(a: argparse.Namespace, cfg: Any) -> list[dict[str, Any]]:
    rules = load_rules(a.rules or cfg.rules_path or None, cfg.disabled_rules)
    prot = build_protector(cfg, a.admin_ip, detect=False if a.no_detect_admin else None)
    an = Analyzer(RuleSet(rules), cfg, prot)
    stats = ParseStats()
    for p in a.paths:
        for ev in iter_events(p, a.format, stats):
            an.feed(ev)
    return an.finish().blocks


# ------------------------------------------------------------------ commands
def cmd_watch(a: argparse.Namespace) -> int:
    from iisguard.watcher import Watcher

    try:
        mgr, cfg = _manager(a, 0)
        rules = RuleSet(load_rules(a.rules or cfg.rules_path or None, cfg.disabled_rules))
    except (ConfigError, RuleError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    mode = "LIVE (will change the firewall)" if a.live else "DRY-RUN (logs only)"
    print(f"watching {len(a.paths)} file(s) with backend {mgr.backend.name}: {mode}. Ctrl+C to stop.")
    w = Watcher(cfg, rules, a.paths, mgr, mgr.protector, a.format, a.live, a.from_start, a.interval)
    try:
        w.run(a.poll, a.max_steps)
    except (FirewallError, UnknownFormat) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_block(a: argparse.Namespace) -> int:
    try:
        if a.block_cmd == "list":
            st = BlockManager(choose_backend("auto"), Protector, state_dir(a.state_dir) / "blocks.json")
            rows = st.entries_list()
            if a.json:
                print(json.dumps(rows, indent=2))
            else:
                print(f"{len(rows)} blocked IP(s)")
                for r in rows:
                    exp = time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["expires"]))
                    print(
                        f"  {r['ip']:<40} score={r['score']:<7} expires={exp}{' (expired)' if r['expired'] else ''}  {','.join(r.get('rules', []))}"
                    )
            return 0
        mgr, cfg = _manager(a, 0)
        if a.block_cmd == "sync":
            res = mgr.sync(_scan_blocks(a, cfg), a.live)
        elif a.block_cmd == "unban":
            res = mgr.unban(a.ips, a.live)
        elif a.block_cmd == "rollback":
            res = mgr.rollback(a.live)
        else:
            res = mgr.clear(a.live)
        _show(res)
    except (ConfigError, RuleError, UnknownFormat, FirewallError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_fix(a: argparse.Namespace) -> int:
    from iisguard.fix import headers, machinekey, php_ini, uploads, wp_upgrade_dir

    state = state_dir(a.state_dir)
    try:
        if a.fix_cmd == "list":
            for b in fixbase.list_backups(state):
                print(f"{b['id']}  {b['fix']}  {', '.join(b['files'])}")
            return 0
        if a.fix_cmd == "rollback":
            bid, files = fixbase.rollback(state, a.id, a.force)
            print(f"restored backup {bid}: " + ", ".join(files))
            return 0
        if a.fix_cmd == "machinekey":
            plan = machinekey.plan(a.paths, a.all_hardcoded)
        elif a.fix_cmd == "headers":
            plan = headers.plan(a.path, a.hsts)
        elif a.fix_cmd == "uploads":
            plan = uploads.plan(a.dirs, a.server, a.handlers)
        elif a.fix_cmd == "php-ini":
            plan = php_ini.plan(a.ini, a.post_max_size)
        else:
            plan = wp_upgrade_dir.plan(a.wp_root)
        print(plan.diff() if plan.changes else "No file changes planned.")
        for k, v in plan.snippets.items():
            print(f"\n--- {k} snippet ---\n{v}")
        for n in plan.notes:
            print(f"note: {n}")
        if not plan.changes:
            return 0
        if not a.apply:
            print(
                "\nDRY-RUN: nothing was written. Re-run with --apply to make these changes (a backup is created first)."
            )
            return 0
        bid = fixbase.apply_plan(plan, state)
        print(f"\nApplied. Backup id: {bid}\nUndo with: iisguard fix rollback --id {bid}")
    except (fixbase.FixError, ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_quarantine(a: argparse.Namespace) -> int:
    from iisguard.fix import quarantine

    state = state_dir(a.state_dir)
    try:
        if a.list:
            for m in quarantine.list_items(state):
                print(f"{m['id']}  {m['sha256'][:16]}  {m['path']}  {m.get('reason', '')}")
            return 0
        if a.restore:
            print("restored to " + quarantine.restore(a.restore, state, a.force))
            return 0
        if not a.file:
            print("error: give a file, or --list / --restore ID", file=sys.stderr)
            return 2
        info = quarantine.plan(a.file)
        print(f"would quarantine {info['path']} ({info['size']} bytes, sha256 {info['sha256']})")
        if not a.apply:
            print("DRY-RUN: nothing moved. Re-run with --apply.")
            return 0
        qid = quarantine.apply(a.file, state, a.reason)
        print(f"moved. Restore with: iisguard quarantine --restore {qid}")
    except (fixbase.FixError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_service(a: argparse.Namespace) -> int:
    from iisguard import service

    if a.action == "install" and not a.logs:
        print("error: install needs --logs FILE [FILE...]", file=sys.stderr)
        return 2
    xml_name = str(Path(a.write_dir) / "iisguard-task.xml") if a.write_dir else "iisguard-task.xml"
    sp = service.plan(
        a.action, [str(Path(x).resolve()) for x in a.logs], a.backend, a.live, a.config, xml_path=xml_name
    )
    for path, content in sp.files.items():
        print(f"--- {path} ---\n{content}")
    for c in sp.commands:
        print(f"command: {c.display()}")
    for n in sp.notes:
        print(f"note: {n}")
    if a.write_dir:
        Path(a.write_dir).mkdir(parents=True, exist_ok=True)
        for path, content in sp.files.items():
            out = Path(a.write_dir) / Path(path).name
            out.write_text(content, encoding="utf-8")
            print(f"wrote {out} (copy it into place yourself)")
        return 0
    if not a.apply:
        print("DRY-RUN: nothing was installed or started. Re-run with --apply (as Administrator/root).")
        return 0
    for m in service.apply(sp, default_runner):
        print(m)
    return 0
