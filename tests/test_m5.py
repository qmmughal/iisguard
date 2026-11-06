from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest

import synth
from conftest import run_scan
from iisguard import cli, exposure, rules_update
from iisguard.config import Config
from iisguard.export import crowdsec, iplist, modsec, re2_compatible, sigma, yara
from iisguard.firewall.safety import Protector, bundled_cdn_ranges
from iisguard.report import render as rr
from iisguard.report.model import Finding, from_document
from iisguard.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def rules() -> list[Any]:
    return load_rules()


# ------------------------------------------------------------------ Sigma
def test_sigma_is_valid_and_complete(rules: list[Any]) -> None:
    pytest.importorskip("sigma")
    from sigma.collection import SigmaCollection

    text = sigma.export(rules, when="2026-11-07")
    coll = SigmaCollection.from_yaml(text)
    expected = [r for r in rules if r.field in sigma.FIELD_MAP and r.score >= 10]
    assert len(coll.rules) == len(expected)
    assert all(not r.errors for r in coll.rules)
    assert len({str(r.id) for r in coll.rules}) == len(expected)  # unique, stable ids
    assert text == sigma.export(rules, when="2026-11-07")  # deterministic


def test_sigma_content(rules: list[Any]) -> None:
    import yaml

    docs = list(yaml.safe_load_all(sigma.export(rules, when="2026-11-07")))
    by = {d["title"]: d for d in docs}
    shell = by["iisguard - webshell-post-image"]
    sel = shell["detection"]["selection"]
    assert sel["cs-method"] == "POST" and "c-uri-stem|re" in sel
    assert shell["id"] == str(uuid.uuid5(sigma.NS, "webshell-post-image"))
    sp = by["iisguard - sharepoint-spinstall"]
    assert "cve.2025.53770" in sp["tags"] and sp["level"] == "critical"
    for d in docs:
        pat = next(iter(v for k, v in d["detection"]["selection"].items() if k.endswith("|re")))
        re.compile(pat.replace("(?i)", "", 1), re.I)


# ------------------------------------------------------------------ YARA
def test_yara_compiles_and_matches_only_markers(tmp_path: Path) -> None:
    yx = pytest.importorskip("yara_x")
    import webroot_fixture as wf

    text = yara.export()
    rules = yx.compile(text)
    scanner = yx.Scanner(rules)
    root = tmp_path / "w"
    wf.build(root)
    hit, clean_hit = set(), set()
    for rel, data in {**wf.PLANTED, **wf.CLEAN}.items():
        matched = [m.identifier for m in scanner.scan(data).matching_rules]
        if matched:
            (hit if rel in wf.PLANTED else clean_hit).add(rel)
    assert not clean_hit, f"YARA matched clean files: {clean_hit}"
    assert {
        "wp-content/uploads/2026/11/img-cache.php",
        "images/banner.png",
        "site1/.user.ini",
        "app/UpdateChecker.aspx",
    } <= hit
    assert "iisguard_php_auto_prepend_config" in [
        m.identifier for m in scanner.scan(wf.PLANTED["site1/.user.ini"]).matching_rules
    ]
    assert "iisguard_script_inside_image" in [
        m.identifier for m in scanner.scan(wf.PLANTED["images/banner.png"]).matching_rules
    ]


def test_yara_structure_without_compiler() -> None:
    text = yara.export()
    names = re.findall(r"^rule (\w+) \{", text, re.M)
    assert len(names) == len(set(names)) >= 5
    assert text.count("{") == text.count("}")
    assert "iisguard_php_webshell_strong" in names and "iisguard_asp_webshell_strong" in names


# ------------------------------------------------------------------ ModSecurity
@pytest.mark.parametrize("mode", modsec.MODES)
def test_modsec_structure(rules: list[Any], mode: str) -> None:
    text = modsec.export(rules, mode)
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    ids: list[int] = []
    pending_chain = False
    for ln in lines:
        m = re.fullmatch(r'\s*SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"', ln)
        assert m, f"malformed SecRule: {ln[:120]}"
        var, op, acts = m.groups()
        assert var and op.startswith(("@rx ", "!@rx ", "@contains "))
        if op.lstrip("!").startswith("@rx "):
            re.compile(op.lstrip("!")[4:].replace('\\"', '"').replace("(?i)", "", 1), re.I)
        found = re.search(r"\bid:(\d+)", acts)
        if found:
            ids.append(int(found.group(1)))
            assert "phase:2" in acts and "msg:'" in acts
            if mode == "block" and "chain" not in acts:
                assert "deny,status:403" in acts
            if mode == "detect" and "chain" not in acts:
                assert "pass,log" in acts and "deny" not in acts
            if mode == "crs" and "chain" not in acts:
                assert "setvar:'tx.inbound_anomaly_score_pl1=+%{tx." in acts
        pending_chain = "chain" in acts and "id:" in acts
    assert not pending_chain and len(ids) == len(set(ids)) and all(9_000_000 <= i <= 9_999_999 for i in ids)


def test_modsec_chain_for_method_rules(rules: list[Any]) -> None:
    text = modsec.export(rules)
    block = text.split("webshell-post-image", 1)[1][:600]
    assert 'SecRule REQUEST_METHOD "@rx ^(POST)$"' in text and ",chain" in block
    with pytest.raises(ValueError):
        modsec.export(rules, "explode")
    assert "PHP_SESSION_UPLOAD_PROGRESS" in text


# ------------------------------------------------------------------ CrowdSec
def test_crowdsec_scenarios_valid(rules: list[Any]) -> None:
    import yaml

    text, skipped = crowdsec.export(rules, Config())
    docs = list(yaml.safe_load_all(text))
    names = [d["name"] for d in docs]
    assert len(names) == len(set(names)) and "iisguard/login-bruteforce" in names
    for d in docs:
        assert d["type"] in ("leaky", "trigger") and d["groupby"] == "evt.Meta.source_ip" and d["blackhole"]
        assert d["filter"].strip().startswith("evt.Meta.log_type")
        if d["type"] == "leaky":
            assert int(d["capacity"]) >= 1 and re.fullmatch(r"\d+s", d["leakspeed"])
        for pat in re.findall(r"`([^`]*)`", d["filter"]):
            assert re2_compatible(pat), f"{d['name']} has a non-RE2 pattern"
            re.compile(pat.replace("(?i)", "", 1))
    assert skipped == []  # every shipped rule is RE2-safe (exclusions use the `exclude` field, not lookahead)
    assert any("!(evt.Meta.http_path matches" in d["filter"] for d in docs)
    assert crowdsec.blocklist(["45.1.1.1", "45.1.1.2"]) == "45.1.1.1\n45.1.1.2\n"


# ------------------------------------------------------------------ IP lists
def test_iplist_formats_and_protection() -> None:
    blocks = [{"ip": "45.1.1.1", "score": 300, "rules": ["a"]}, {"ip": "2a01:db8::1", "score": 120}, {"ip": synth.ADMIN_IP, "score": 999},
              {"ip": "10.0.0.1", "score": 500}, {"ip": "not-an-ip", "score": 1}, {"ip": "45.1.1.1", "score": 5}]  # fmt: skip
    rows, dropped = iplist.collect(blocks, Protector(admin_ips=[synth.ADMIN_IP]))
    assert [r["ip"] for r in rows] == ["45.1.1.1", "2a01:db8::1"]
    assert {d["reason"] for d in dropped} == {"admin-session", "non-public-address", "invalid-ip"}
    assert iplist.render(rows, "txt") == "45.1.1.1\n2a01:db8::1\n"
    parsed = list(csv.reader(io.StringIO(iplist.render(rows, "csv"))))
    assert parsed[0] == ["ip", "score", "rules"] and parsed[1][0] == "45.1.1.1"
    assert json.loads(iplist.render(rows, "json"))[1]["ip"] == "2a01:db8::1"
    nft = iplist.render(rows, "nft")
    assert "blocked4 { 45.1.1.1 }" in nft and "blocked6 { 2a01:db8::1 }" in nft
    with pytest.raises(ValueError):
        iplist.render(rows, "xml")


# ------------------------------------------------------------------ CLI exports
def test_cli_export_all(tmp_path: Path, logs: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    for kind in ("sigma", "yara", "modsec"):
        out = tmp_path / f"{kind}.out"
        assert cli.main(["export", kind, "--out", str(out)]) == 0 and out.stat().st_size > 200
    capsys.readouterr()
    scan_json = tmp_path / "scan.json"
    cli.main(
        ["scan", str(logs["attack_iis"]), "--output-format", "json", "--no-detect-admin", "--admin-ip", synth.ADMIN_IP]
    )
    scan_json.write_text(capsys.readouterr().out)
    cs = tmp_path / "cs"
    assert (
        cli.main(
            [
                "export",
                "crowdsec",
                "--out",
                str(cs),
                "--from",
                str(scan_json),
                "--admin-ip",
                synth.ADMIN_IP,
                "--no-detect-admin",
            ]
        )
        == 0
    )
    bl = (cs / "iisguard-blocklist.txt").read_text().split()
    assert synth.A_PHP2SHELL in bl and synth.ADMIN_IP not in bl
    capsys.readouterr()
    assert cli.main(["export", "iplist", "--from", str(scan_json), "--format", "csv", "--no-detect-admin"]) == 0
    assert synth.A_SCANNER in capsys.readouterr().out
    assert cli.main(["export", "iplist"]) == 2
    assert cli.main(["export", "modsec", "--mode", "block", "--id-base", "9900000"]) == 0
    assert "id:9900000," in capsys.readouterr().out


# ------------------------------------------------------------------ reports
def make_docs(logs: dict[str, Path]) -> list[dict[str, Any]]:
    rep = run_scan([logs["attack_iis"]])
    scan = rep.to_dict()
    audit = {"inventory": 2, "findings": [
        {"cve": "CVE-2026-109618", "product": "php", "found": "8.3.30", "fixed": "8.3.36", "kev_due": "2026-10-29", "status": "vulnerable", "in_kev": True, "location": "C:/php/php.exe"},
        {"cve": "CVE-2026-109618", "product": "php", "found": "8.4.27", "fixed": "8.4.27", "kev_due": "", "status": "ok", "in_kev": True, "location": ""}]}  # fmt: skip
    hunt = {"files": [{"path": "C:\\sites\\<script>.php", "score": 100, "severity": "critical", "reasons": ["x"]}],
            "secrets": [{"path": "/srv/.env", "id": "anthropic-key", "severity": "critical", "detail": "key: sk-a***[53 chars]", "line": 1, "reachable": None}],
            "webconfig": {"files": 1, "findings": [{"path": "/srv/web.config", "id": "debug-enabled", "severity": "medium", "detail": "d", "fix": "", "key_fingerprint": ""}], "skipped": []},
            "processes": {"examined": 1, "findings": [{"parent": "w3wp.exe", "child": "cmd.exe", "cmdline": "cmd /c whoami", "severity": "high", "rule": "web-worker-spawned-shell"}]}}  # fmt: skip
    expo = {
        "exposure": {
            "findings": [
                {
                    "severity": "medium",
                    "title": "Header: Strict-Transport-Security missing",
                    "location": "example.com",
                    "detail": "",
                    "rule": "hsts-missing",
                }
            ]
        }
    }
    return [scan, audit, hunt, expo]


def test_report_all_formats(logs: dict[str, Path]) -> None:
    findings = [f for d in make_docs(logs) for f in from_document(d)]
    assert {f.source for f in findings} == {"scan", "audit", "hunt", "exposure"}
    assert not any(f.title.endswith("[ok]") for f in findings)  # fixed items are omitted
    assert findings[0].severity == "critical"  # sorted worst first
    c = list(csv.reader(io.StringIO(rr.to_csv(findings))))
    assert c[0][:3] == ["source", "severity", "title"] and len(c) == len(findings) + 1
    js = json.loads(rr.to_json(findings))
    assert js["count"] == len(findings)
    sarif = json.loads(rr.to_sarif(findings))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["tool"]["driver"]["name"] == "iisguard"
    res = sarif["runs"][0]["results"]
    assert len(res) == len(findings) and all(
        r["level"] in ("error", "warning", "note") and r["message"]["text"] for r in res
    )
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in res)
    uris = [
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for r in res
        for loc in r.get("locations", [])
        if "physicalLocation" in loc
    ]
    assert any(u.startswith("file:///") for u in uris)


def test_html_is_single_file_offline_and_escaped(logs: dict[str, Path]) -> None:
    findings = [f for d in make_docs(logs) for f in from_document(d)]
    html = rr.to_html(findings)
    assert "<script>.php" not in html and "&lt;script&gt;.php" in html  # attacker-controlled text is escaped
    assert "prefers-color-scheme:dark" in html and "data-theme" in html
    assert not re.search(r"(?:src|href)=[\"']https?://", html) and "<link" not in html and "@import" not in html
    assert "default-src 'none'" in html


def test_csv_formula_injection_neutralized() -> None:
    out = rr.to_csv([Finding("hunt", "high", '=HYPERLINK("http://x")', "+cmd", "@SUM(1)", "-1")])
    row = next(csv.reader(io.StringIO(out.splitlines()[1] + "\n")))
    assert all(cell.startswith("'") for cell in (row[2], row[3], row[4], row[5]))


def test_cli_report(tmp_path: Path, logs: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    inp = []
    for i, d in enumerate(make_docs(logs)):
        p = tmp_path / f"in{i}.json"
        p.write_text(json.dumps(d))
        inp.append(str(p))
    for fmt in rr.FORMATS:
        out = tmp_path / f"r.{fmt}"
        assert cli.main(["report", *inp, "--format", fmt, "--out", str(out)]) == 0 and out.stat().st_size > 100
    (tmp_path / "bad.json").write_text("[1,2]")
    assert cli.main(["report", str(tmp_path / "bad.json")]) == 2


# ------------------------------------------------------------------ exposure
class Fake:
    def __init__(self, routes: dict[str, exposure.Response | None], default: exposure.Response | None = None) -> None:
        self.routes, self.default, self.seen = routes, default, []  # type: ignore[var-annotated]

    def __call__(self, url: str) -> exposure.Response | None:
        self.seen.append(url)
        return self.routes.get(url, self.default)


HEAD = [("Server", "Apache/2.4.52"), ("X-Powered-By", "PHP/8.3.1"), ("Set-Cookie", "sid=1; Path=/")]


def run_exposure(routes: dict[str, exposure.Response | None], **kw: Any) -> tuple[list[Finding], dict[str, Any], Fake]:
    default = exposure.Response(404, [], b"nope")
    fake = Fake(routes, default)
    f, info = exposure.check(
        "https://example.com", kw.pop("owner", "example.com"), get=fake,
        tls=kw.pop("tls", lambda h: {"version": "TLSv1.3", "days_left": 90, "error": ""}),
        dns=kw.pop("dns", lambda h: ["93.184.216.34"]), origin=kw.pop("origin", lambda ip, h: None), delay=0, sleep=lambda s: None, **kw)  # fmt: skip
    return f, info, fake


def titles(findings: list[Finding]) -> list[str]:
    return [f.title for f in findings]


def test_exposure_refuses_unconfirmed_host() -> None:
    fake = Fake({})
    with pytest.raises(ValueError, match="refusing"):
        exposure.check("https://example.com", "other.org", get=fake)
    with pytest.raises(ValueError, match="domain name"):
        exposure.check("https://93.184.216.34", "93.184.216.34", get=fake)
    assert fake.seen == []  # not a single request was made


def test_exposure_findings() -> None:
    routes: dict[str, exposure.Response | None] = {
        "https://example.com/": exposure.Response(200, HEAD, b"<html>hello</html>"),
        "http://example.com/": exposure.Response(200, [], b"plain"),
        "https://example.com/uploads/": exposure.Response(200, [], b"<title>Index of /uploads</title>"),
        "https://example.com/.env": exposure.Response(200, [], b"APP_KEY=base64:xxxx"),
        "https://example.com/wp-login.php": exposure.Response(200, [], b"<form>login</form>"),
        "https://example.com/admin/": exposure.Response(403, [], b"forbidden"),
    }
    f, info, fake = run_exposure(routes, tls=lambda h: {"version": "TLSv1.3", "days_left": 5, "error": ""})
    t = titles(f)
    assert any("Strict-Transport-Security missing" in x for x in t) and any("X-Content-Type-Options" in x for x in t)
    assert any("Banner: server: Apache/2.4.52" in x for x in t) and any("Banner: x-powered-by" in x for x in t)
    assert any("Directory listing" in x for x in t) and any("Sensitive file reachable: /.env" in x for x in t)
    assert any("Admin/login panel reachable" in x and "wp-login.php" in x for x in t)
    assert not any("/admin/" in x for x in t)  # 403 is fine
    assert any("certificate expires in 5" in x for x in t) and any("without redirecting to HTTPS" in x for x in t)
    assert any("lacks Secure" in x for x in t) and any("lacks HttpOnly" in x for x in t)
    assert info["requests"] <= exposure.MAX_REQUESTS and all(
        u.startswith(("https://example.com", "http://example.com")) for u in fake.seen
    )


def test_exposure_clean_site_and_soft_404() -> None:
    good = [("Strict-Transport-Security", "max-age=31536000"), ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
            ("Content-Security-Policy", "default-src 'self'"), ("Server", "nginx")]  # fmt: skip
    routes = {
        "https://example.com/": exposure.Response(200, good, b"ok"),
        "http://example.com/": exposure.Response(301, [("Location", "https://example.com/")], b""),
    }
    f, _, _ = run_exposure(routes)
    assert [x for x in f if x.severity in ("medium", "high")] == []
    # a site that answers 200 + the same body for ANY path must not produce sensitive-file / panel findings
    fake_default = exposure.Response(200, good, b"<html>Not found, but 200</html>")
    fk = Fake(
        {"http://example.com/": exposure.Response(301, [("Location", "https://example.com/")], b"")}, fake_default
    )
    f3, _ = exposure.check("https://example.com", "example.com", get=fk, tls=lambda h: {"version": "TLSv1.3", "days_left": 90, "error": ""},
                           dns=lambda h: [], origin=lambda ip, h: None, delay=0, sleep=lambda s: None)  # fmt: skip
    assert not [x for x in f3 if "Sensitive" in x.title or "Admin/login" in x.title]


def test_exposure_origin_direct_check() -> None:
    cf_ip = bundled_cdn_ranges()["cloudflare"][0].split("/")[0]
    routes = {"https://example.com/": exposure.Response(200, [("Strict-Transport-Security", "x")], b"ok")}
    f, info, _ = run_exposure(routes, dns=lambda h: [cf_ip])
    assert info["cdn"] == "cloudflare" and any("Origin-direct check skipped" in x.title for x in f)
    f2, _, _ = run_exposure(
        routes, dns=lambda h: [cf_ip], origin_ip="203.0.113.9", origin=lambda ip, h: exposure.Response(200, [], b"ok")
    )
    assert any(x.severity == "high" and "Origin server answers directly" in x.title for x in f2)
    f3, _, _ = run_exposure(routes, dns=lambda h: [cf_ip], origin_ip="203.0.113.9", origin=lambda ip, h: None)
    assert any("did not answer directly" in x.title for x in f3)
    with pytest.raises(ValueError, match="origin-ip"):
        run_exposure(routes, dns=lambda h: [cf_ip], origin_ip="nope")


def test_exposure_tls_problem_and_cli_guard(capsys: pytest.CaptureFixture[str]) -> None:
    f, _, _ = run_exposure(
        {}, tls=lambda h: {"version": "", "days_left": None, "error": "certificate not trusted: self signed"}
    )
    assert any(x.severity == "high" and x.title.startswith("TLS") for x in f)
    assert cli.main(["exposure", "--url", "https://example.com", "--confirm-owner", "not-example.com"]) == 2
    assert "refusing" in capsys.readouterr().err


def test_exposure_request_cap() -> None:
    f, info, fake = run_exposure({})
    assert info["requests"] <= exposure.MAX_REQUESTS and len(fake.seen) <= exposure.MAX_REQUESTS


# ------------------------------------------------------------------ update-rules
def make_index(
    tmp_path: Path, version: str, data: bytes, sha: str | None = None, name: str = "web-core"
) -> dict[str, bytes]:
    index = {
        "schema": 1,
        "packs": [
            {
                "name": name,
                "version": version,
                "file": "web-core/rules.yaml",
                "sha256": sha or hashlib.sha256(data).hexdigest(),
            }
        ],
    }
    base = "https://example.org/rule-packs/"
    return {base + "index.json": json.dumps(index).encode(), base + "web-core/rules.yaml": data}


def fetcher(files: dict[str, bytes]) -> Any:
    def f(url: str) -> bytes:
        if url not in files:
            raise OSError("404 " + url)
        return files[url]

    return f


def bundled_yaml() -> bytes:
    return (ROOT / "src" / "iisguard" / "rules" / "rules.yaml").read_bytes()


IDX = "https://example.org/rule-packs/index.json"


def test_update_installs_valid_newer_pack_and_it_is_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    extra = (
        bundled_yaml()
        + b"""- id: custom-test-rule
  category: recon
  score: 20
  severity: low
  field: path
  pattern: '/iisguard-canary'
  tests:
    match:
      - '/iisguard-canary'
    no_match:
      - '/other'
"""
    )
    files = make_index(tmp_path, "2099.01.01-1", extra)
    msgs = rules_update.update_rules(IDX, fetcher(files), tmp_path)
    assert "installed 2099.01.01-1" in msgs[0]
    monkeypatch.setenv("IISGUARD_STATE_DIR", str(tmp_path))
    assert "custom-test-rule" in {r.id for r in load_rules()}  # picked up automatically
    assert rules_update.update_rules(IDX, fetcher(files), tmp_path)[0].endswith("already up to date (2099.01.01-1)")
    assert rules_update.update_rules(IDX, fetcher(files), tmp_path, check_only=True)
    (tmp_path / "rules" / "web-core" / "rules.yaml").write_text(
        "- id: broken"
    )  # a corrupted pack falls back to bundled
    assert "wp-setup-config-probe" in {r.id for r in load_rules()}


def test_update_rejects_bad_hash_bad_tests_old_version_and_traversal(tmp_path: Path) -> None:
    data = bundled_yaml()
    with pytest.raises(rules_update.UpdateError, match="SHA-256"):
        rules_update.update_rules(IDX, fetcher(make_index(tmp_path, "2099.01.01-1", data, sha="0" * 64)), tmp_path)
    bad = data.replace(b"'/wp-admin/setup-config.php'", b"'/nothing-matches-this'", 1)
    with pytest.raises(rules_update.UpdateError, match="failed validation"):
        rules_update.update_rules(IDX, fetcher(make_index(tmp_path, "2099.01.01-1", bad)), tmp_path)
    assert not (tmp_path / "rules" / "web-core" / "rules.yaml").exists()
    assert (
        "up to date" in rules_update.update_rules(IDX, fetcher(make_index(tmp_path, "2000.01.01-1", data)), tmp_path)[0]
    )
    idx = make_index(tmp_path, "2099.01.01-1", data)
    evil = json.loads(idx[IDX])
    evil["packs"][0]["file"] = "../../etc/passwd"
    idx[IDX] = json.dumps(evil).encode()
    with pytest.raises(rules_update.UpdateError, match="unsafe"):
        rules_update.update_rules(IDX, fetcher(idx), tmp_path)
    with pytest.raises(rules_update.UpdateError, match="https"):
        rules_update.fetch_url("http://example.org/x")


def test_update_cdn_ranges_refresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    files = {
        rules_update.CLOUDFLARE_URLS[0]: b"198.51.100.0/24\n",
        rules_update.CLOUDFLARE_URLS[1]: b"2001:db8::/32\n",
        rules_update.CLOUDFRONT_URL: json.dumps({"prefixes": [{"ip_prefix": "203.0.113.0/24", "service": "CLOUDFRONT"}, {"ip_prefix": "1.1.1.0/24", "service": "S3"}],
                                                 "ipv6_prefixes": [{"ipv6_prefix": "2001:db8:1::/48", "service": "CLOUDFRONT"}]}).encode()}  # fmt: skip
    msgs = rules_update.update_cdn(fetcher(files), tmp_path)
    assert msgs == ["cloudflare: 2 ranges", "cloudfront: 2 ranges"]
    monkeypatch.setenv("IISGUARD_STATE_DIR", str(tmp_path))
    ranges = bundled_cdn_ranges()
    assert (
        ranges["cloudfront"] == ["203.0.113.0/24", "2001:db8:1::/48"] and ranges["cloudflare"][0] == "198.51.100.0/24"
    )
    files[rules_update.CLOUDFRONT_URL] = b'{"prefixes": []}'
    with pytest.raises(rules_update.UpdateError, match="empty"):
        rules_update.update_cdn(fetcher(files), tmp_path)


def test_published_rule_pack_index_matches_bundled_rules() -> None:
    index = json.loads((ROOT / "rule-packs" / "index.json").read_text(encoding="utf-8"))
    pack = index["packs"][0]
    data = (ROOT / "rule-packs" / pack["file"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == pack["sha256"], "run: python scripts/build_rule_pack_index.py"
    assert pack["version"] == rules_update.bundled_version() and data.replace(b"\r\n", b"\n") == bundled_yaml().replace(
        b"\r\n", b"\n"
    )
    assert rules_update.validate_pack(ROOT / "rule-packs" / pack["file"]) >= 15


def test_cli_update_rules_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rules_update, "fetch_url", fetcher(make_index(tmp_path, "2099.01.01-1", bundled_yaml())))
    monkeypatch.setattr(rules_update, "INDEX_URL", IDX)
    assert cli.main(["update-rules", "--check", "--index-url", IDX, "--state-dir", str(tmp_path / "s")]) == 0
    assert "update available" in capsys.readouterr().out
    assert (
        cli.main(
            ["update-rules", "--index-url", "http://insecure.example/index.json", "--state-dir", str(tmp_path / "s")]
        )
        == 2
    )
