from __future__ import annotations

import json
from pathlib import Path

import pytest

import synth
from conftest import run_scan
from iisguard import cli, miniyaml
from iisguard.config import Config, ConfigError, load_config
from iisguard.firewall.safety import Protector, bundled_cdn_ranges, detect_admin_ips
from iisguard.logs import UnknownFormat, iter_events
from iisguard.models import LogEvent, ParseStats
from iisguard.rules import RuleError, RuleSet, load_rules

EXPECTED_RULES = {
    "php2shell-upload-progress", "wp-setup-config-probe", "wp-upgrade-dir-probe", "viewstate-long-get",
    "webshell-post-image", "webshell-updatechecker", "sharepoint-toolpane-edit", "exchange-owa-auth-aspx",
    "wp-uploads-php", "scanner-user-agent", "sensitive-file-probe", "sqli-basic",
}  # fmt: skip


def hit_ids(rep) -> set[tuple[str, str]]:  # type: ignore[no-untyped-def]
    return {(h.ip, h.rule_id) for h in rep.hits}


# ------------------------------------------------------------------ rules
def _sample(s: str) -> str:
    return s.replace("<LONG1000>", "A" * 1000)


@pytest.mark.parametrize("rule", load_rules(), ids=lambda r: r.id)
def test_rule_own_tests(rule):  # type: ignore[no-untyped-def]
    assert rule.rx is not None
    for s in rule.tests_match:
        assert rule.rx.search(_sample(s)), f"{rule.id} should match {s!r}"
    for s in rule.tests_no_match:
        assert not rule.rx.search(_sample(s)), f"{rule.id} must NOT match {s!r}"


def test_rules_bad_pack_rejected(tmp_path: Path) -> None:
    p = tmp_path / "r.yaml"
    p.write_text("- id: x\n  category: c\n  score: 1\n  severity: low\n  field: path\n  pattern: 'a'\n")
    with pytest.raises(RuleError, match="missing keys"):
        load_rules(str(p))


def test_miniyaml_matches_pyyaml() -> None:
    yaml = pytest.importorskip("yaml")
    from importlib import resources

    text = resources.files("iisguard.rules").joinpath("rules.yaml").read_text(encoding="utf-8")
    assert miniyaml.loads(text) == yaml.safe_load(text)


def test_disabled_rule_not_matched() -> None:
    rs = RuleSet(load_rules(disabled=["wp-setup-config-probe"]))
    ev = LogEvent(path="/wp-admin/setup-config.php", uri="/wp-admin/setup-config.php", method="GET")
    assert not rs.match(ev)


# ------------------------------------------------------------------ parsers
def test_formats_agree_on_timestamps(logs: dict[str, Path]) -> None:
    def firsts(name: str) -> tuple[float, str, str]:
        e = next(iter_events(str(logs[name])))
        return e.ts, e.ip, e.path

    assert firsts("attack_iis") == firsts("attack_nginx") == firsts("attack_apache") == firsts("attack_json")


def test_autodetect_php_error_and_apache_error(logs: dict[str, Path]) -> None:
    st = ParseStats()
    evs = list(iter_events(str(logs["php_error"]), "auto", st))
    assert st.formats == {"php-error": 1}
    assert any(e.level == "fatal" for e in evs) and any(e.level == "crash" for e in evs)
    ev2 = list(iter_events(str(logs["apache_error"])))
    assert ev2[0].ip == "45.9.1.10" and ev2[0].level == "fatal"


def test_unknown_format_raises(tmp_path: Path) -> None:
    p = tmp_path / "x.log"
    p.write_text("this is not a log\nnor this\n")
    with pytest.raises(UnknownFormat):
        list(iter_events(str(p)))


def test_malformed_lines_counted_not_fatal(tmp_path: Path) -> None:
    p = tmp_path / "x.log"
    p.write_text(
        '1.2.3.4 - - [07/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"\ngarbage line that is long enough\n'
    )
    st = ParseStats()
    assert len(list(iter_events(str(p), "nginx", st))) == 1
    assert st.bad == 1


def test_url_encoded_evasion_is_decoded(tmp_path: Path) -> None:
    p = tmp_path / "x.log"
    p.write_text(
        '9.9.9.9 - - [07/Nov/2026:10:00:00 +0000] "GET /wp-admin/%2573etup-config.php HTTP/1.1" 404 5 "-" "ua"\n'
    )
    rep = run_scan([p])
    assert ("9.9.9.9", "wp-setup-config-probe") in hit_ids(rep)


# ------------------------------------------------------------------ detection
@pytest.mark.parametrize("name", ["attack_iis", "attack_nginx", "attack_apache", "attack_json"])
def test_attack_log_detections(logs: dict[str, Path], name: str) -> None:
    rep = run_scan([logs[name]])
    got = hit_ids(rep)
    assert (synth.A_PHP2SHELL, "php2shell-upload-progress") in got
    assert (synth.A_WP, "wp-setup-config-probe") in got
    assert (synth.A_WP, "wp-upgrade-dir-probe") in got
    assert (synth.A_VIEWSTATE, "viewstate-long-get") in got
    assert (synth.A_SHELL_C2, "webshell-post-image") in got
    assert (synth.A_SHELL_C2, "webshell-updatechecker") in got
    assert (synth.A_SHAREPOINT, "sharepoint-toolpane-edit") in got
    assert (synth.A_EXCHANGE, "exchange-owa-auth-aspx") in got
    assert (synth.A_PHP2SHELL, "wp-uploads-php") in got
    assert (synth.A_PHP2SHELL, "sqli-basic") in got
    assert (synth.A_SCANNER, "scanner-user-agent") in got
    assert (synth.A_SCANNER, "sensitive-file-probe") in got
    assert (synth.A_SCANNER, "behav-scan-4xx") in got
    assert (synth.A_BRUTE, "behav-bruteforce") in got
    assert (synth.A_FLOOD, "behav-flood") in got
    spray = {ip for ip, rid in got if rid == "behav-spray"}
    assert set(synth.SPRAY_IPS) <= spray
    assert not (spray & {synth.A_BRUTE})
    assert any(f["id"] == "host-password-spray" for f in rep.host_findings)
    assert len({n["subnet"] for n in rep.subnets} & {"185.100.1.0/24", "185.100.2.0/24"}) == 2


def test_attackers_blocked_spray_ips_individually_below_threshold_not(logs: dict[str, Path]) -> None:
    rep = run_scan([logs["attack_iis"]])
    blocked = {b["ip"] for b in rep.blocks}
    assert {synth.A_PHP2SHELL, synth.A_SCANNER, synth.A_BRUTE, synth.A_SHELL_C2} <= blocked
    # a single short flood (80 pts) or one spray attempt (70 pts) is reported but stays below the block score
    assert not blocked & set(synth.SPRAY_IPS)
    assert synth.A_FLOOD not in blocked


@pytest.mark.parametrize("name", ["clean_iis", "clean_nginx"])
def test_clean_traffic_zero_detections_zero_blocks(logs: dict[str, Path], name: str) -> None:
    rep = run_scan([logs[name]])
    assert rep.hits == [] and rep.host_findings == [] and rep.blocks == [] and rep.subnets == []


def test_mixed_log_clean_ips_never_flagged(logs: dict[str, Path]) -> None:
    rep = run_scan([logs["attack_nginx"]])
    clean_ips = {e.ip for e in synth.clean_events()}
    assert not clean_ips & {h.ip for h in rep.hits}


def test_php_crash_burst(logs: dict[str, Path]) -> None:
    rep = run_scan([logs["php_error"]])
    assert [f["id"] for f in rep.host_findings] == ["host-php-crash-burst"]
    assert rep.blocks == []
    rep2 = run_scan([logs["apache_error"]])
    assert any(f["id"] == "host-php-crash-burst" for f in rep2.host_findings)


# ------------------------------------------------------------------ safety
def test_admin_ip_can_never_be_blocked(logs: dict[str, Path]) -> None:
    unprotected = run_scan([logs["attack_iis"]])
    assert synth.ADMIN_IP in {b["ip"] for b in unprotected.blocks}  # would be blocked otherwise
    prot = Protector(admin_ips=[synth.ADMIN_IP])
    rep = run_scan([logs["attack_iis"]], prot)
    assert synth.ADMIN_IP not in {b["ip"] for b in rep.blocks}
    assert {
        "ip": synth.ADMIN_IP,
        "score": rep.scores[synth.ADMIN_IP],
        "reason": "admin-session",
    } in rep.protected


def test_admin_ip_never_blocked_even_with_absurd_score() -> None:
    cfg = Config(block_score=1)
    prot = Protector(admin_ips=["45.9.1.99"])
    for ip in ("45.9.1.99", "::ffff:45.9.1.99"):
        assert prot.reason(ip) == "admin-session"
    assert cfg.block_score == 1


def test_detect_admin_from_ssh_env_and_netstat() -> None:
    assert detect_admin_ips(
        env={"SSH_CONNECTION": "45.9.1.99 5555 10.0.0.5 22"}, platform="linux", runner=lambda c: ""
    ) == {"45.9.1.99"}
    netstat = (
        "  TCP    10.0.0.5:3389    45.9.1.98:50000   ESTABLISHED\n"
        "  TCP    10.0.0.5:443     45.9.1.77:50001   ESTABLISHED\n"
        "  TCP    10.0.0.5:3389    45.9.1.55:50002   TIME_WAIT\n"
    )
    assert detect_admin_ips(env={}, platform="win32", runner=lambda c: netstat) == {"45.9.1.98"}
    ss = "ESTAB 0 0 10.0.0.5:22 45.9.1.97:40000\nESTAB 0 0 [::1]:80 [::1]:5\n"
    assert detect_admin_ips(env={}, platform="linux", runner=lambda c: ss) == {"45.9.1.97"}


@pytest.mark.parametrize(
    ("ip", "why"),
    [
        ("10.1.2.3", "non-public-address"), ("192.168.0.9", "non-public-address"), ("127.0.0.1", "non-public-address"),
        ("169.254.1.1", "non-public-address"), ("::1", "non-public-address"), ("not-an-ip", "invalid-ip"),
        ("172.67.1.1", "cdn-or-load-balancer"), ("2606:4700::1", "cdn-or-load-balancer"),
        ("45.9.1.200", "allowlisted"), ("45.9.1.201", "server-own-ip"), ("45.9.1.99", "admin-session"),
    ],
)  # fmt: skip
def test_protector_reasons(ip: str, why: str) -> None:
    cdn = [r for rs in bundled_cdn_ranges().values() for r in rs]
    p = Protector(["45.9.1.200/32"], cdn, ["45.9.1.99"], ["45.9.1.201"])
    assert p.reason(ip) == why


def test_public_ip_not_protected() -> None:
    assert Protector().reason("45.9.1.50") is None


def test_block_cap_evicts_lowest_scores(tmp_path: Path) -> None:
    rows = []
    for i in range(1, 6):  # ip i gets i probe hits -> increasing scores
        for _ in range(i):
            rows.append(
                f'45.7.0.{i} - - [07/Nov/2026:10:00:00 +0000] "GET /wp-admin/setup-config.php HTTP/1.1" 200 5 "-" "ua"'
            )
    for i in range(1, 6):  # plus a fixed high-confidence hit so all cross the threshold
        rows.append(f'45.7.0.{i} - - [07/Nov/2026:10:00:01 +0000] "GET /UpdateChecker.aspx HTTP/1.1" 200 5 "-" "ua"')
    p = tmp_path / "a.log"
    p.write_text("\n".join(rows) + "\n")
    rep = run_scan([p], cfg=Config(max_blocks=2))
    assert [b["ip"] for b in rep.blocks] == ["45.7.0.5", "45.7.0.4"]
    assert {e["ip"] for e in rep.evicted} == {"45.7.0.1", "45.7.0.2", "45.7.0.3"}


# ------------------------------------------------------------------ config & cli
def test_config_precedence_and_validation(tmp_path: Path) -> None:
    f = tmp_path / "c.json"
    f.write_text(json.dumps({"block_score": 50, "allowlist": ["1.2.3.0/24"], "bogus": 1}))
    cfg = load_config(f, env={"IISGUARD_BLOCK_SCORE": "75", "IISGUARD_ADMIN_IPS": "9.9.9.9, 8.8.8.8"})
    assert cfg.block_score == 75 and cfg.admin_ips == ["9.9.9.9", "8.8.8.8"]
    assert any("bogus" in w for w in cfg.warnings)
    f.write_text(json.dumps({"allowlist": ["nope"]}))
    with pytest.raises(ConfigError):
        load_config(f, env={})
    f.write_text(json.dumps({"block_score": "high"}))
    with pytest.raises(ConfigError):
        load_config(f, env={})


def test_yaml_config(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text("block_score: 120\nallowlist:\n  - 1.2.3.4\n")
    assert load_config(f, env={}).allowlist == ["1.2.3.4"]


def test_cli_help_lists_every_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    for cmd in ("scan", "watch", "audit", "fim", "hunt", "exposure", "block", "fix", "quarantine",
                "export", "report", "service", "update-rules"):  # fmt: skip
        assert cmd in out


def test_cli_scan_json_and_fail_on(logs: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["scan", str(logs["attack_iis"]), "--output-format", "json", "--no-detect-admin",
                   "--admin-ip", synth.ADMIN_IP, "--fail-on", "high"])  # fmt: skip
    data = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert synth.ADMIN_IP not in {b["ip"] for b in data["blocks"]}
    assert cli.main(["scan", str(logs["clean_iis"]), "--no-detect-admin", "--fail-on", "low"]) == 0


def test_cli_unimplemented_command_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hunt"]) == 2
    assert "M3" in capsys.readouterr().err


def test_out_of_order_timestamps_do_not_fake_a_flood(tmp_path: Path) -> None:
    # 200 requests from one IP whose timestamps alternate 23:xx / 00:xx (time going backwards):
    rows = []
    for i in range(200):
        h = "23" if i % 2 else "00"
        rows.append(f'45.6.0.1 - - [07/Nov/2026:{h}:00:{i % 60:02d} +0000] "GET /p{i} HTTP/1.1" 200 5 "-" "ua"')
    p = tmp_path / "a.log"
    p.write_text("\n".join(rows) + "\n")
    assert run_scan([p]).hits == []
