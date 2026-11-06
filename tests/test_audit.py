from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from iisguard import cli
from iisguard.audit import dotnet, php, wordpress
from iisguard.audit.engine import Auditor, Finding
from iisguard.audit.inventory import Item, load_inventory
from iisguard.audit.kev import KevError, build_snapshot, bundled_snapshot, is_web_facing, load_kev
from iisguard.audit.versions import is_distro_build, parse_version

FIXTURE = Path(__file__).parent / "fixtures" / "inventory.json"


def rows(findings: list[Finding]) -> dict[tuple[str, str, str], Finding]:
    return {(f.cve, f.product, f.found): f for f in findings}


# ------------------------------------------------------------------ versions
@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("8.3.35", "8.3.36"), ("8.3.9", "8.3.36"), ("8.5.12RC1", "8.5.12"), ("7.1.3", "7.1.4"),
        ("10.0.20348.5000", "10.0.20348.5761"), ("8.0.28", "8.0.31"), ("8.3", "8.3.1"), ("9.0.20-rc.1", "9.0.20"),
    ],
)  # fmt: skip
def test_version_ordering(a: str, b: str) -> None:
    assert parse_version(a) < parse_version(b)
    assert parse_version(b) > parse_version(a)


def test_version_equality_ignores_trailing_zeros() -> None:
    assert parse_version("8.3") == parse_version("8.3.0")
    assert parse_version("8.3.36").branch() == "8.3"


def test_bad_version_raises() -> None:
    with pytest.raises(ValueError):
        parse_version("not-a-version")


def test_distro_detection() -> None:
    assert is_distro_build("8.3.6-0ubuntu0.24.04.5")
    assert is_distro_build("8.2.20-1+deb12u1")
    assert not is_distro_build("8.3.36")


# ------------------------------------------------------------------ KEV loading
def test_bundled_snapshot_contains_php_cves() -> None:
    snap = bundled_snapshot()
    ids = {v["cveID"] for v in snap["vulnerabilities"]}
    assert {"CVE-2026-109618", "CVE-2026-109619", "CVE-2026-119977"} <= ids


def test_offline_never_calls_network(tmp_path: Path) -> None:
    def boom(url: str) -> dict[str, Any]:
        raise AssertionError("network used in offline mode")

    kev = load_kev(offline=True, cache_dir=tmp_path, fetch=boom)
    assert kev.source == "snapshot" and kev.get("CVE-2026-109618")


def test_download_cached_and_stale_fallback(tmp_path: Path) -> None:
    feed = {"catalogVersion": "9", "dateReleased": "x", "vulnerabilities": [
        {"cveID": "CVE-2026-109618", "vendorProject": "PHP Group", "product": "PHP", "dueDate": "2026-10-29"}]}  # fmt: skip
    calls: list[str] = []

    def fetch(url: str) -> dict[str, Any]:
        calls.append(url)
        return feed

    k1 = load_kev(cache_dir=tmp_path, fetch=fetch)
    assert k1.source == "network" and calls
    k2 = load_kev(cache_dir=tmp_path, fetch=fetch)  # fresh cache, no second download
    assert k2.source == "cache" and len(calls) == 1

    def down(url: str) -> dict[str, Any]:
        raise OSError("offline")

    k3 = load_kev(cache_dir=tmp_path, fetch=down, now=time.time() + 3 * 86400)
    assert k3.source == "stale-cache" and k3.get("CVE-2026-109618")


def test_network_failure_falls_back_to_snapshot(tmp_path: Path) -> None:
    def down(url: str) -> dict[str, Any]:
        raise OSError("no route")

    assert load_kev(cache_dir=tmp_path, fetch=down).source == "snapshot"


def test_malformed_feed_rejected() -> None:
    with pytest.raises(KevError):
        build_snapshot({"vulnerabilities": [{"cveID": "nope"}]})


def test_web_facing_filter() -> None:
    assert is_web_facing({"vendorProject": "PHP Group", "product": "PHP"})
    assert is_web_facing({"vendorProject": "Microsoft", "product": "SharePoint"})
    assert not is_web_facing({"vendorProject": "Apple", "product": "Multiple Products"})


# ------------------------------------------------------------------ audit on the fixture inventory
@pytest.fixture(scope="module")
def result() -> dict[tuple[str, str, str], Finding]:
    kev = load_kev(offline=True, cache_dir=Path("nonexistent-cache-dir"))
    return rows(Auditor(kev).run(load_inventory(FIXTURE)))


def test_php_versions(result: dict[tuple[str, str, str], Finding]) -> None:
    f = result[("CVE-2026-109618", "php", "8.3.30")]
    assert (f.status, f.fixed, f.kev_due) == ("vulnerable", "8.3.36", "2026-10-29")
    assert result[("CVE-2026-109619", "php", "8.2.34")].fixed == "8.2.35"
    assert result[("CVE-2026-109618", "php", "8.4.27")].status == "ok"
    assert result[("CVE-2026-109618", "php", "8.5.12")].status == "ok"
    eol = result[("CVE-2026-109618", "php", "8.1.30")]
    assert eol.status == "eol" and "end-of-life" in eol.fixed


def test_php_distro_build_is_verify_not_vulnerable(result: dict[tuple[str, str, str], Finding]) -> None:
    f = result[("CVE-2026-109618", "php", "8.3.6-0ubuntu0.24.04.5")]
    assert f.status == "verify" and "backport" in f.action.lower()


def test_php_upload_progress_config(result: dict[tuple[str, str, str], Finding]) -> None:
    assert result[("CVE-2026-115560", "php", "8.3.30")].status == "config"
    assert "session.upload_progress.enabled=0" in result[("CVE-2026-115560", "php", "8.3.30")].fixed
    assert result[("CVE-2026-115560", "php", "8.4.27")].status == "ok"
    assert result[("CVE-2026-115560", "php", "8.1.30")].status == "verify"  # value unknown


def test_dotnet(result: dict[tuple[str, str, str], Finding]) -> None:
    assert result[("CVE-2026-69304", "Microsoft.AspNetCore.App", "8.0.28")].fixed == "8.0.31"
    assert result[("CVE-2026-69304", "Microsoft.AspNetCore.App", "9.0.20")].status == "ok"
    sc = result[("CVE-2026-69304", "Microsoft.AspNetCore.App", "10.0.9")]
    assert sc.status == "vulnerable" and sc.fixed == "10.0.12"
    assert result[("CVE-2026-69304", "Microsoft.NETCore.App", "6.0.36")].status == "eol"
    assert any(f.cve == "CVE-2026-96230" and f.status == "manual" for f in result.values())


def test_wordpress(result: dict[tuple[str, str, str], Finding]) -> None:
    assert result[("CVE-2026-119977", "wordpress", "7.1.4")].status == "ok"
    vuln = Auditor(None).run([i for i in load_inventory(FIXTURE) if i.product == "wordpress" and i.version == "7.1.3"])
    assert {f.status for f in vuln} == {"vulnerable", "verify"}  # vulnerable + leftover upgrade folder
    assert any(f.fixed == "7.1.4" for f in vuln)
    assert result[("CVE-2026-119977", "wordpress", "7.0.7")].fixed == "7.0.8"
    assert result[("CVE-2026-119977", "wordpress", "6.5.2")].status == "verify"  # backport version not verified
    assert result[("CVE-2026-119977", "wordpress", "7.1.4")].kev_due == "2026-11-06"


def test_sharepoint_exchange_windows(result: dict[tuple[str, str, str], Finding]) -> None:
    sp = result[("CVE-2026-102866", "sharepoint", "16.0.20326.20100")]
    assert sp.status == "vulnerable" and sp.fixed == "16.0.20326.20190"
    assert result[("CVE-2026-102866", "sharepoint", "16.0.20326.20190")].status == "ok"
    ex = result[("CVE-2026-70571", "exchange", "15.2.1544.11")]
    assert ex.status == "manual" and "not published" in ex.fixed
    w = result[("CVE-2026-70247", "windows", "10.0.20348.5000")]
    assert w.status == "vulnerable" and w.fixed == "10.0.20348.5761"
    assert result[("CVE-2026-78459", "windows", "10.0.20348.5761")].status == "ok"
    assert result[("CVE-2026-70247", "windows", "10.0.26100.9000")].fixed == "10.0.26100.9711"  # Win11 client
    assert result[("CVE-2026-70247", "windows", "10.0.26100.33000")].fixed == "10.0.26100.33650"  # Server 2025


def test_no_unverified_numbers_for_manual_entries() -> None:
    from iisguard.audit.engine import load_known

    for e in load_known()["entries"]:
        if e["status"] == "manual":
            assert "fixed" not in e and "fixed_build_se" not in e, e["id"]
        assert e["sources"], e["id"]


# ------------------------------------------------------------------ collectors (pure parsing, no system access)
def test_parse_php_outputs() -> None:
    assert php.parse_version_output("PHP 8.3.30 (cli) (built: Oct  2 2026 10:00:00) (NTS)\nCopyright") == (
        "8.3.30",
        "cli",
    )
    ini = "session.upload_progress.cleanup => On => On\nsession.upload_progress.enabled => Off => On\n"
    assert php.parse_upload_progress(ini) == "Off"
    items = php.collect(binaries=["x"], runner=lambda c: "PHP 8.2.35 (fpm-fcgi) (built: x)" if c[1] == "-v" else "")
    assert items[0].version == "8.2.35" and "upload_progress" not in items[0].extra


def test_parse_dotnet_list_runtimes() -> None:
    out = (
        "Microsoft.AspNetCore.App 8.0.28 [C:\\Program Files\\dotnet\\shared\\Microsoft.AspNetCore.App]\n"
        "Microsoft.NETCore.App 9.0.20 [/usr/share/dotnet/shared/Microsoft.NETCore.App]\n"
    )
    items = dotnet.parse_list_runtimes(out)
    assert [(i.version, i.extra["runtime_name"]) for i in items] == [
        ("8.0.28", "Microsoft.AspNetCore.App"), ("9.0.20", "Microsoft.NETCore.App")
    ]  # fmt: skip


def test_self_contained_detection(tmp_path: Path) -> None:
    app = tmp_path / "shop"
    app.mkdir()
    deps = {
        "libraries": {"runtimepack.Microsoft.AspNetCore.App.Runtime.win-x64/8.0.28": {}, "Newtonsoft.Json/13.0.3": {}}
    }
    (app / "shop.deps.json").write_text(json.dumps(deps))
    (tmp_path / "other.deps.json").write_text(json.dumps({"libraries": {"Foo/1.0.0": {}}}))
    items = dotnet.scan_self_contained([str(tmp_path)])
    assert [(i.version, i.extra["self_contained"]) for i in items] == [("8.0.28", True)]


def test_wordpress_collector(tmp_path: Path) -> None:
    site = tmp_path / "site"
    (site / "wp-includes").mkdir(parents=True)
    (site / "wp-includes" / "version.php").write_text("<?php\n$wp_version = '7.1.3';\n$wp_db_version = 1;\n")
    (site / "wp-content" / "upgrade" / "wordpress-7.1.4").mkdir(parents=True)
    items = wordpress.collect([str(tmp_path)])
    assert len(items) == 1 and items[0].version == "7.1.3"
    assert items[0].extra["upgrade_dir_present"] is True


def test_inventory_validation(tmp_path: Path) -> None:
    p = tmp_path / "i.json"
    p.write_text(json.dumps({"items": [{"product": "mystery", "version": "1"}]}))
    with pytest.raises(ValueError, match="unknown product"):
        load_inventory(p)


# ------------------------------------------------------------------ CLI
def test_cli_audit_offline_table(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["audit", "--kev", "--offline", "--inventory", str(FIXTURE), "--cache-dir", "none-here",
                   "--fail-on-vulnerable"])  # fmt: skip
    out = capsys.readouterr().out
    assert rc == 1
    for expect in ("8.3.36", "8.0.31", "7.1.4", "16.0.20326.20190", "10.0.20348.5761", "2026-10-29"):
        assert expect in out
    assert "snapshot" in out


def test_cli_audit_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["audit", "--offline", "--inventory", str(FIXTURE), "--output-format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kev"] is None and len(data["findings"]) > 20


def test_cli_audit_bad_inventory(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert cli.main(["audit", "--inventory", str(tmp_path / "missing.json")]) == 2


def test_item_defaults() -> None:
    assert Item("php", "8.3.36").extra == {}


def test_kev_watch_is_recent_and_capped() -> None:
    kev = load_kev(offline=True, cache_dir=Path("none-here"))
    items = [Item("php", "8.3.36"), Item("exchange", "15.2.1544.11")]
    a = Auditor(kev)
    a.run(items)
    watch = a.kev_watch(items)
    assert watch
    assert len([w for w in watch if w["product"] == "php"]) <= 8
    assert not {w["cve"] for w in watch} & {"CVE-2012-1823", "CVE-2016-10033"}  # old entries excluded
