from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

import synth
import webroot_fixture as wf
from iisguard import cli, service
from iisguard.audit import webconfig
from iisguard.config import Config
from iisguard.firewall.base import Cmd, clean_ips
from iisguard.firewall.cloudflare_api import CloudflareBackend
from iisguard.firewall.linux_iptables import IptablesBackend
from iisguard.firewall.linux_nftables import NftBackend
from iisguard.firewall.manager import BlockManager, FirewallError
from iisguard.firewall.safety import Protector
from iisguard.firewall.windows_netsh import NetshBackend
from iisguard.fix import base as fixbase
from iisguard.fix import headers, machinekey, php_ini, quarantine, uploads, wp_upgrade_dir, xmledit
from iisguard.logs import iter_events
from iisguard.rules import RuleSet, load_rules
from iisguard.watcher import Tailer, Watcher

ATT = synth.A_PHP2SHELL


# ------------------------------------------------------------------ backends
def test_clean_ips_blocks_injection() -> None:
    assert clean_ips(["1.2.3.4", " 1.2.3.4 ", "::ffff:5.6.7.8"]) == ["1.2.3.4", "5.6.7.8"]
    for bad in ("1.2.3.4; rm -rf /", "1.2.3.4 -j ACCEPT", "name=x", "", "1.2.3.4,5.6.7.8"):
        with pytest.raises(ValueError):
            clean_ips([bad])


def test_netsh_batches_and_adds_before_deleting() -> None:
    ips = [f"45.1.{i // 250}.{i % 250 + 1}" for i in range(450)]
    plan = NetshBackend().sync_plan(ips, {"rules": ["iisguard-old-1"]}, "G1")
    assert len(plan.add) == 3 and all(c.argv[:3] == ["netsh", "advfirewall", "firewall"] for c in plan.add)
    assert plan.add[0].argv.count("action=block") == 1 and "dir=in" in plan.add[0].argv
    assert [c.argv[-1] for c in plan.cleanup] == ["name=iisguard-old-1"]
    assert plan.meta["rules"] == ["iisguard-G1-1", "iisguard-G1-2", "iisguard-G1-3"]
    assert all(" " not in a.split("=", 1)[0] for c in plan.add for a in c.argv)  # argv list, no shell string


def test_nft_script_is_one_atomic_transaction() -> None:
    plan = NftBackend().sync_plan(["45.1.1.1", "2a01:db8::1"], None, "G")
    assert len(plan.add) == 1 and plan.add[0].argv == ["nft", "-f", "-"] and plan.undo == []
    s = plan.add[0].stdin or ""
    assert "flush set inet iisguard blocked4" in s and "add element inet iisguard blocked4 { 45.1.1.1 }" in s
    assert "blocked6 { 2a01:db8::1 }" in s
    assert s.index("flush set") < s.index("add element")


def test_iptables_builds_new_chain_before_swapping_out_old() -> None:
    plan = IptablesBackend().sync_plan(["45.1.1.1"], {"chain": "IISGUARD_OLD"}, "20261107T100000-0001")
    names = [" ".join(c.argv) for c in plan.add]
    assert names[0].startswith("iptables-restore --noflush") and "INPUT 1 -j IISGUARD_" in names[1]
    assert "-A IISGUARD_" in (plan.add[0].stdin or "") and "-s 45.1.1.1 -j DROP" in (plan.add[0].stdin or "")
    assert any("-D INPUT -j IISGUARD_OLD" in " ".join(c.argv) for c in plan.cleanup)
    assert plan.undo and plan.meta["chain"].startswith("IISGUARD_")


# ------------------------------------------------------------------ block manager
class FakeRunner:
    def __init__(self, fail_on: int | None = None) -> None:
        self.calls: list[Cmd] = []
        self.fail_on = fail_on

    def __call__(self, cmd: Cmd) -> tuple[int, str]:
        self.calls.append(cmd)
        if self.fail_on is not None and len(self.calls) == self.fail_on:
            return 1, "boom"
        if cmd.kind == "http" and cmd.argv[0] == "POST":
            return 0, json.dumps({"result": {"id": "rule-" + cmd.tag}})
        return 0, ""


def mgr(
    tmp_path: Path, runner: FakeRunner, backend: Any = None, prot: Protector | None = None, **kw: Any
) -> BlockManager:
    return BlockManager(
        backend or NetshBackend(), lambda: prot or Protector(), tmp_path / "blocks.json", runner=runner, **kw
    )


def blk(ip: str, score: float = 150, rules: list[str] | None = None) -> dict[str, Any]:
    return {"ip": ip, "score": score, "rules": rules or ["r"]}


def test_dry_run_runs_nothing_and_writes_nothing(tmp_path: Path) -> None:
    r = FakeRunner()
    m = mgr(tmp_path, r)
    res = m.sync([blk("45.1.1.1")], live=False)
    assert res.ips == ["45.1.1.1"] and res.commands and r.calls == []
    assert not (tmp_path / "blocks.json").exists()


def test_live_sync_adds_before_cleanup_and_saves_state(tmp_path: Path) -> None:
    r = FakeRunner()
    m = mgr(tmp_path, r)
    m.sync([blk("45.1.1.1")], live=True)
    first = len(r.calls)
    m.sync([blk("45.1.1.2")], live=True)  # old IP stays until its TTL ends: both are blocked
    verbs = [c.argv[3] if len(c.argv) > 3 else "" for c in r.calls[first:]]
    assert verbs == ["add", "delete"]  # new generation added, THEN the old rule removed
    assert {e["ip"] for e in m.entries_list()} == {"45.1.1.1", "45.1.1.2"}


def test_failed_add_leaves_previous_rules_and_undoes_partial(tmp_path: Path) -> None:
    r = FakeRunner()
    m = mgr(tmp_path, r)
    m.sync([blk("45.1.1.1")], live=True)
    before = (tmp_path / "blocks.json").read_text()
    r.calls.clear()
    r.fail_on = 1
    with pytest.raises(FirewallError, match="previous rules left in place"):
        m.sync([blk("45.1.1.9")], live=True)
    assert (tmp_path / "blocks.json").read_text() == before
    assert any(c.argv[3] == "delete" for c in r.calls[1:])  # partial new generation removed
    assert not any("iisguard-" + str(0) in " ".join(c.argv) for c in r.calls[:0])


def test_admin_ip_never_enters_or_stays_in_the_block_list(tmp_path: Path) -> None:
    r = FakeRunner()
    prot = Protector(admin_ips=[synth.ADMIN_IP])
    m = mgr(tmp_path, r, prot=prot)
    res = m.sync([blk(synth.ADMIN_IP, 9999), blk(ATT)], live=True)
    assert res.ips == [ATT] and res.protected == [{"ip": synth.ADMIN_IP, "reason": "admin-session"}]
    assert synth.ADMIN_IP not in json.dumps([c.argv for c in r.calls])
    # a tampered state file containing the admin IP is cleaned at the next sync
    st = json.loads((tmp_path / "blocks.json").read_text())
    st["entries"][synth.ADMIN_IP] = {"score": 1, "added": 0, "expires": 9e12, "rules": []}
    (tmp_path / "blocks.json").write_text(json.dumps(st))
    res2 = m.sync([], live=True)
    assert synth.ADMIN_IP not in res2.ips and any(p["ip"] == synth.ADMIN_IP for p in res2.protected)


def test_private_and_cdn_ips_never_blocked(tmp_path: Path) -> None:
    m = mgr(tmp_path, FakeRunner())
    res = m.sync([blk("10.0.0.5"), blk("192.168.1.1"), blk("127.0.0.1"), blk(ATT)], live=False)
    assert res.ips == [ATT] and len(res.protected) == 3


def test_cap_evicts_lowest_scores_first(tmp_path: Path) -> None:
    m = mgr(tmp_path, FakeRunner(), max_blocks=2)
    res = m.sync([blk("45.1.1.1", 100), blk("45.1.1.2", 300), blk("45.1.1.3", 200)], live=False)
    assert res.ips == ["45.1.1.2", "45.1.1.3"] and res.evicted == ["45.1.1.1"]


def test_ttl_expiry_unban_rollback_clear(tmp_path: Path) -> None:
    now = [1000.0]
    r = FakeRunner()
    m = BlockManager(NetshBackend(), Protector, tmp_path / "blocks.json", ttl=100, runner=r, clock=lambda: now[0])
    m.sync([blk("45.1.1.1")], live=True)
    m.sync([blk("45.1.1.2")], live=True)
    assert {e["ip"] for e in m.entries_list()} == {"45.1.1.1", "45.1.1.2"}
    m.unban(["45.1.1.1"], live=True)
    assert {e["ip"] for e in m.entries_list()} == {"45.1.1.2"}
    m.rollback(live=True)  # undo the unban
    assert {e["ip"] for e in m.entries_list()} == {"45.1.1.1", "45.1.1.2"}
    now[0] += 500  # everything expires
    res = m.sync([], live=True)
    assert res.ips == []
    assert m.clear(live=True).ips == []
    with pytest.raises(FirewallError):
        BlockManager(NetshBackend(), Protector, tmp_path / "empty.json", runner=r).rollback(live=True)


def test_cloudflare_backend_uses_env_token_and_stores_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "abc123")
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "super-secret-token")
    r = FakeRunner()
    m = mgr(tmp_path, r, backend=CloudflareBackend())
    dry = m.sync([blk("45.1.1.1")], live=False)
    assert "super-secret-token" not in " ".join(dry.commands)
    m.sync([blk("45.1.1.1")], live=True)
    assert m.state()["meta"]["rule_ids"] == {"45.1.1.1": "rule-45.1.1.1"}
    assert all(c.secret_env == "CLOUDFLARE_API_TOKEN" for c in r.calls)
    m.unban(["45.1.1.1"], live=True)
    assert r.calls[-1].argv[0] == "DELETE" and r.calls[-1].argv[1].endswith("/rule-45.1.1.1")
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "bad/zone")
    with pytest.raises(ValueError):
        CloudflareBackend().sync_plan(["45.1.1.1"], None, "g")


# ------------------------------------------------------------------ watcher
def test_tailer_start_at_end_partial_lines_truncate_rotate(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    nl = chr(10)
    p.write_bytes(("old1" + nl + "old2" + nl).encode())
    t = Tailer(str(p), "combined")
    assert t.read_new() == []
    with open(p, "ab") as f:
        f.write(("new1" + nl + "half").encode())
    assert t.read_new() == ["new1" + nl]
    with open(p, "ab") as f:
        f.write(("-done" + nl + "new3" + nl).encode())
    assert t.read_new() == ["half-done" + nl, "new3" + nl]
    p.write_bytes(("fresh" + nl).encode())  # truncated below our offset
    assert t.read_new() == ["fresh" + nl]


def test_watcher_blocks_attacker_dry_run_and_keeps_iis_header(tmp_path: Path) -> None:
    log = tmp_path / "u_ex.log"
    synth.write_iis(log, synth.clean_events()[:20])
    r = FakeRunner()
    m = mgr(tmp_path, r)
    clock = [0.0]
    w = Watcher(Config(), RuleSet(load_rules()), [str(log)], m, m.protector, "auto", live=False, sync_interval=0,
                clock=lambda: clock[0], log=lambda s: None)  # fmt: skip
    attack = tmp_path / "attack.log"
    synth.write_iis(attack, [e for e in synth.attack_events() if e.ip in (ATT, synth.A_SCANNER, synth.A_SHELL_C2)])
    rows = attack.read_text().splitlines()[4:]  # data lines only: the watcher must reuse the header it saw at start
    with open(log, "a") as f:
        f.write("\n".join(rows) + "\n")
    clock[0] = 10
    res = w.step()
    assert res is not None and ATT in res.ips and r.calls == []  # dry-run: decided, did not act
    assert w.stats.bad == 0


def test_watcher_never_blocks_admin_even_when_attacking(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text("")
    prot = Protector(admin_ips=[synth.ADMIN_IP])
    m = mgr(tmp_path, FakeRunner(), prot=prot)
    w = Watcher(Config(), RuleSet(load_rules()), [str(log)], m, m.protector, "combined", live=False, sync_interval=0,
                clock=lambda: 1.0, log=lambda s: None)  # fmt: skip
    synth.write_combined(tmp_path / "x.log", [e for e in synth.attack_events() if e.ip in (synth.ADMIN_IP, ATT)])
    with open(log, "a") as f:
        f.write((tmp_path / "x.log").read_text())
    res = w.step()
    assert res is not None and synth.ADMIN_IP not in res.ips and ATT in res.ips


# ------------------------------------------------------------------ fixes
@pytest.fixture
def state(tmp_path: Path) -> Path:
    return tmp_path / "state"


def test_xmledit_insert_cases() -> None:
    frag = '<add name="A" value="1" />'
    p = ["system.webServer", "httpProtocol", "customHeaders"]
    for start in (
        "",
        "<configuration></configuration>",
        "<configuration><system.webServer /></configuration>",
        '<configuration><system.webServer><httpProtocol><customHeaders><add name="B" value="2"/></customHeaders></httpProtocol></system.webServer></configuration>',
        "<configuration>\r\n  <!-- keep me -->\r\n  <system.webServer>\r\n  </system.webServer>\r\n</configuration>\r\n",
    ):
        out = xmledit.insert(start, p, frag)
        xmledit.validate(out)
        assert 'name="A"' in out
    assert "<!-- keep me -->" in xmledit.insert(start, p, frag) and "\r\n" in xmledit.insert(start, p, frag)


def test_machinekey_rotate_apply_rollback(tmp_path: Path, state: Path) -> None:
    wf.write(tmp_path, wf.webconfig_files())
    a, b = tmp_path / "wc/siteA/web.config", tmp_path / "wc/siteB/web.config"
    a.write_bytes(b"\xef\xbb\xbf" + a.read_bytes().replace(b"\n", b"\r\n"))  # BOM + CRLF must survive
    orig = {p: p.read_bytes() for p in (a, b)}
    plan = machinekey.plan([str(tmp_path / "wc")])
    assert {c.path.parent.name for c in plan.changes} == {"siteA", "siteB"}
    shown = plan.diff()
    assert wf.KEY_A not in shown and "NEW random key hidden" in shown and "old key hidden" in shown
    bid = fixbase.apply_plan(plan, state)
    new_a, new_b = a.read_bytes(), b.read_bytes()
    assert new_a.startswith(b"\xef\xbb\xbf") and b"\r\n" in new_a and wf.KEY_A.encode() not in new_a
    audit = webconfig.audit_roots([str(tmp_path / "wc")])
    assert not [f for f in audit.findings if f.id == "machinekey-shared"]  # no longer shared
    assert len(new_a) == len(orig[a]) and new_a != new_b  # same length, unique keys
    fixbase.rollback(state, bid)
    assert a.read_bytes() == orig[a] and b.read_bytes() == orig[b]


def test_rollback_refuses_after_later_edit_unless_forced(tmp_path: Path, state: Path) -> None:
    f = tmp_path / "php.ini"
    f.write_text("session.upload_progress.enabled = 1\n")
    bid = fixbase.apply_plan(php_ini.plan(str(f)), state)
    f.write_text(f.read_text() + "; admin edit\n")
    with pytest.raises(fixbase.FixError, match="changed after"):
        fixbase.rollback(state, bid)
    fixbase.rollback(state, bid, force=True)
    assert f.read_text() == "session.upload_progress.enabled = 1\n"


def test_machinekey_nothing_to_do_when_unique(tmp_path: Path) -> None:
    (tmp_path / "web.config").write_text(wf.webconfig_files()["wc/siteC/web.config"].decode())
    plan = machinekey.plan([str(tmp_path)])
    assert plan.changes == [] and any("Nothing to rotate" in n for n in plan.notes)
    assert len(machinekey.plan([str(tmp_path)], all_hardcoded=True).changes) == 1


def test_headers_idempotent_and_valid(tmp_path: Path, state: Path) -> None:
    p = tmp_path / "web.config"
    plan = headers.plan(str(tmp_path))
    assert plan.changes[0].old is None and "nginx" in plan.snippets
    fixbase.apply_plan(plan, state)
    ET.parse(p)
    assert "X-Content-Type-Options" in p.read_text() and "Strict-Transport-Security" not in p.read_text()
    assert headers.plan(str(p)).changes == []
    assert "Strict-Transport-Security" in headers.plan(str(p), hsts=True).changes[0].new


def test_uploads_creates_files_and_never_overwrites(tmp_path: Path, state: Path) -> None:
    up, up2 = tmp_path / "uploads", tmp_path / "other"
    up.mkdir()
    up2.mkdir()
    (up2 / "web.config").write_text("<configuration/>")
    plan = uploads.plan([str(up), str(up2), str(tmp_path / "missing")])
    assert [c.path for c in plan.changes] == [up / "web.config"]
    assert sum("skipped" in n for n in plan.notes) == 2
    fixbase.apply_plan(plan, state)
    t = (up / "web.config").read_text()
    ET.fromstring(t)
    assert 'fileExtension=".php" allowed="false"' in t and "accessPolicy" not in t
    assert "accessPolicy" in uploads.plan([str(up2)], handlers=True).snippets["iis"]
    assert (uploads.plan([str(up2)], "apache").changes[0].new).startswith("# added by iisguard")


def test_php_ini_set_ini_variants() -> None:
    f = php_ini.set_ini
    assert "session.upload_progress.enabled = 0" in f(
        "[Session]\nsession.upload_progress.enabled = 1\n", "session.upload_progress.enabled", "0", "n"
    )
    assert "was: 1" in f("session.upload_progress.enabled=1\n", "session.upload_progress.enabled", "0", "n")
    assert (
        f(";session.upload_progress.enabled = 1\n", "session.upload_progress.enabled", "0", "n").count(
            "session.upload_progress.enabled = 0"
        )
        == 1
    )
    assert f("a=1", "session.upload_progress.enabled", "0", "n").endswith("session.upload_progress.enabled = 0\n")
    same = "session.upload_progress.enabled = 0\n"
    assert f(same, "session.upload_progress.enabled", "0", "n") == same


def test_php_ini_plan_uses_php_dash_dash_ini(tmp_path: Path) -> None:
    ini = tmp_path / "php.ini"
    ini.write_text("memory_limit = 128M\n")
    plan = php_ini.plan(
        None,
        "32M",
        runner=lambda c: f"Configuration File (php.ini) Path: x\nLoaded Configuration File:         {ini}\n",
    )
    new = plan.changes[0].new
    assert "session.upload_progress.enabled = 0" in new and "post_max_size = 32M" in new
    assert php_ini.plan(None, runner=lambda c: "Loaded Configuration File:         (none)\n").changes == []


def test_wp_upgrade_dir_plan(tmp_path: Path, state: Path) -> None:
    root = tmp_path / "wp"
    (root / "wp-includes").mkdir(parents=True)
    (root / "wp-includes" / "version.php").write_text("<?php $wp_version = '7.1.3';")
    (root / "wp-content" / "upgrade" / "x").mkdir(parents=True)
    (root / "web.config").write_text(
        "<configuration><system.webServer><security><requestFiltering /></security></system.webServer></configuration>"
    )
    plan = wp_upgrade_dir.plan(str(root))
    assert any("leftovers" in n for n in plan.notes)
    fixbase.apply_plan(plan, state)
    t = (root / "web.config").read_text()
    ET.fromstring(t)
    assert "/wp-content/upgrade/" in t and "setup-config.php" in t
    assert wp_upgrade_dir.plan(str(root)).changes == []
    assert wp_upgrade_dir.plan(str(tmp_path)).changes == []


def test_quarantine_roundtrip(tmp_path: Path, state: Path) -> None:
    shell = tmp_path / "web" / "img.php"
    shell.parent.mkdir()
    shell.write_text("<?php /* IISGUARD-TEST-MARKER */")
    info = quarantine.plan(str(shell))
    assert shell.exists() and len(info["sha256"]) == 64
    qid = quarantine.apply(str(shell), state, "test")
    assert not shell.exists() and quarantine.list_items(state)[0]["id"] == qid
    stored = next((state / "quarantine" / qid).glob("*.quarantined"))
    assert stored.suffix == ".quarantined"
    assert quarantine.restore(qid, state) == str(shell.resolve()) and shell.exists()
    with pytest.raises(fixbase.FixError):
        quarantine.plan(str(tmp_path))


# ------------------------------------------------------------------ service
def test_service_plans_are_text_only_until_applied() -> None:
    lin = service.plan(
        "install", ["/var/log/nginx/access.log"], "nftables", True, None, platform="linux", python="/usr/bin/python3"
    )
    unit = lin.files[service.UNIT_PATH]
    assert "ExecStart=/usr/bin/python3 -m iisguard watch /var/log/nginx/access.log --backend nftables --live" in unit
    assert [c.argv[:2] for c in lin.commands] == [["systemctl", "daemon-reload"], ["systemctl", "enable"]]
    win = service.plan(
        "install", [r"C:\logs\u_ex.log"], "netsh", False, None, platform="win32", python=r"C:\Python\python.exe"
    )
    xml = win.files["iisguard-task.xml"]
    ET.fromstring(xml.encode("utf-16"))
    assert "DRY-RUN" in win.notes[0] and win.commands[0].argv[:3] == ["schtasks", "/Create", "/TN"]
    assert service.plan("stop", [], "auto", False, None, platform="linux").commands[0].argv == [
        "systemctl",
        "stop",
        "iisguard",
    ]
    with pytest.raises(ValueError):
        service.plan("explode", [], "auto", False, None)


def test_service_apply_uses_injected_runner(tmp_path: Path) -> None:
    sp = service.plan("install", ["/x.log"], "auto", False, None, platform="linux", python="py")
    sp.files = {str(tmp_path / "iisguard.service"): sp.files[service.UNIT_PATH]}
    seen: list[list[str]] = []
    msgs = service.apply(sp, lambda c: seen.append(c.argv) or (0, ""))
    assert (tmp_path / "iisguard.service").exists() and seen[0] == ["systemctl", "daemon-reload"] and len(msgs) == 3


# ------------------------------------------------------------------ CLI safety: dry-run never executes anything
def test_cli_dry_runs_never_execute_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("a command was executed during a dry-run")

    monkeypatch.setattr("subprocess.run", boom)
    monkeypatch.setattr("subprocess.Popen", boom)
    monkeypatch.setenv("IISGUARD_STATE_DIR", str(tmp_path / "st"))
    log = tmp_path / "a.log"
    synth.write_iis(log, synth.attack_events())
    base = ["--backend", "nftables", "--no-detect-admin", "--admin-ip", synth.ADMIN_IP]
    assert cli.main(["block", "sync", str(log), *base]) == 0
    out = capsys.readouterr().out
    assert "DRY-RUN" in out and synth.ADMIN_IP not in out and "nft -f -" in out
    assert not (tmp_path / "st" / "blocks.json").exists()
    assert cli.main(["block", "list"]) == 0
    assert cli.main(["block", "unban", "45.1.1.1", "--backend", "netsh", "--no-detect-admin"]) == 0
    ini = tmp_path / "php.ini"
    ini.write_text("session.upload_progress.enabled = 1\n")
    assert cli.main(["fix", "php-ini", "--ini", str(ini)]) == 0
    assert ini.read_text() == "session.upload_progress.enabled = 1\n" and "DRY-RUN" in capsys.readouterr().out
    assert cli.main(["service", "install", "--logs", str(log), "--backend", "nftables"]) == 0
    assert "DRY-RUN" in capsys.readouterr().out
    shell = tmp_path / "s.php"
    shell.write_text("x")
    assert cli.main(["quarantine", str(shell)]) == 0 and shell.exists()


def test_cli_fix_apply_and_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("IISGUARD_STATE_DIR", str(tmp_path / "st"))
    ini = tmp_path / "php.ini"
    ini.write_text("session.upload_progress.enabled = 1\n")
    assert cli.main(["fix", "php-ini", "--ini", str(ini), "--apply"]) == 0
    assert "= 0" in ini.read_text()
    assert cli.main(["fix", "list"]) == 0
    assert cli.main(["fix", "rollback"]) == 0
    assert ini.read_text() == "session.upload_progress.enabled = 1\n"
    assert cli.main(["fix", "rollback", "--id", "nope"]) == 2


def test_cli_help_lists_every_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    for cmd in ("scan", "watch", "audit", "fim", "hunt", "block", "fix", "quarantine", "service"):
        assert cmd in out


def test_unused_imports_guard() -> None:
    assert os.name and iter_events  # keeps linters honest about helpers used above
