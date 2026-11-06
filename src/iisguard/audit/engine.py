"""Match an inventory against known fixed versions and the CISA KEV catalog."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import date, timedelta
from importlib import resources
from typing import Any

from iisguard import miniyaml
from iisguard.audit.inventory import Item
from iisguard.audit.kev import Kev
from iisguard.audit.versions import Version, VersionError, is_distro_build, parse_version

# status values, worst first
STATUS_ORDER = ["vulnerable", "eol", "config", "verify", "manual", "ok"]


@dataclass
class Finding:
    cve: str
    product: str
    found: str
    fixed: str
    kev_due: str
    action: str
    status: str
    location: str = ""
    title: str = ""
    in_kev: bool = False
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_known() -> dict[str, Any]:
    text = resources.files("iisguard.audit").joinpath("data/known_fixed_versions.yaml").read_text(encoding="utf-8")
    try:
        import yaml

        data = yaml.safe_load(text)
    except ImportError:
        data = miniyaml.loads(text)
    if not isinstance(data, dict) or "entries" not in data:
        raise ValueError("known_fixed_versions.yaml: expected 'entries'")
    return data


def _fixed_map(entry: dict[str, Any]) -> dict[str, str]:
    return {str(f["branch"]): str(f["fixed_in"]) for f in entry.get("fixed", [])}


def _truthy(v: Any) -> bool | None:
    if v is None or v == "":
        return None
    return str(v).strip().lower() in ("1", "on", "true", "yes", "enabled")


class Auditor:
    def __init__(self, kev: Kev | None = None, known: dict[str, Any] | None = None) -> None:
        self.kev = kev
        self.known = known or load_known()
        self.entries = {e["id"]: e for e in self.known["entries"]}
        self.findings: list[Finding] = []
        self._manual_done: set[str] = set()

    # ------------------------------------------------------------------ helpers
    def _add(self, entry: dict[str, Any], cve: str, item: Item, fixed: str, status: str, action: str = "") -> None:
        k = self.kev.get(cve) if self.kev else None
        self.findings.append(
            Finding(
                cve=cve,
                product=item.product if not item.extra.get("runtime_name") else str(item.extra["runtime_name"]),
                found=item.version,
                fixed=fixed,
                kev_due=str(k["dueDate"]) if k else "",
                action=action or str(entry.get("action", "")),
                status=status,
                location=item.location,
                title=str(entry.get("title", "")),
                in_kev=k is not None,
                sources=list(entry.get("sources", [])),
            )
        )

    def _manual(self, entry_id: str, item: Item) -> None:
        if entry_id in self._manual_done:
            return
        self._manual_done.add(entry_id)
        e = self.entries[entry_id]
        for cve in e["cves"]:
            self._add(e, cve, item, "not published (verify on MSRC)", "manual")

    def _branch_check(self, entry: dict[str, Any], item: Item, eol_below: Version | None = None) -> None:
        try:
            v = parse_version(item.version)
        except VersionError:
            for cve in entry["cves"]:
                self._add(entry, cve, item, "?", "verify", "Version could not be parsed; check it manually.")
            return
        fixed = _fixed_map(entry).get(v.branch())
        for cve in entry["cves"]:
            if fixed is not None:
                if v >= parse_version(fixed):
                    self._add(entry, cve, item, fixed, "ok")
                elif is_distro_build(item.version):
                    self._add(entry, cve, item, fixed, "verify",
                              "Distro package: fixes are backported without changing the version. Check your "
                              "distro's security tracker for this CVE.")  # fmt: skip
                else:
                    self._add(entry, cve, item, fixed, "vulnerable")
            elif v.branch() in entry.get("eol_branches", []) or (eol_below and v < eol_below):
                latest = max(_fixed_map(entry).values(), key=parse_version, default="a supported release")
                self._add(entry, cve, item, f"none (end-of-life); move to a supported branch, >= {latest}", "eol")
            else:
                newest = max(_fixed_map(entry), key=parse_version, default="")
                if newest and v.nums > parse_version(newest).nums[:2]:
                    self._add(entry, cve, item, "newer branch; confirm it contains the October fixes", "verify")
                else:
                    self._add(entry, cve, item, "unknown branch; check vendor advisory", "verify")

    # ------------------------------------------------------------------ products
    def _php(self, item: Item) -> None:
        self._branch_check(self.entries["php-oct2026-rce"], item)
        e = self.entries["php-session-upload-progress"]
        state = _truthy(item.extra.get("upload_progress"))
        cve = e["cves"][0]
        if state is True:
            self._add(e, cve, item, "no fix yet; set session.upload_progress.enabled=0", "config")
        elif state is None:
            self._add(e, cve, item, "no fix yet", "verify",
                      "Could not read session.upload_progress.enabled. Check php.ini and every FPM pool; "
                      "set it to 0.")  # fmt: skip
        else:
            self._add(e, cve, item, "workaround in place (session.upload_progress.enabled=0)", "ok")

    def _wordpress(self, item: Item) -> None:
        e = self.entries["wordpress-core-upgrade-race"]
        try:
            v = parse_version(item.version)
        except VersionError:
            self._add(e, e["cves"][0], item, "?", "verify", "Version could not be parsed.")
            return
        fixed = _fixed_map(e).get(v.branch())
        if fixed is not None or v > parse_version("7.1.3"):
            self._branch_check(e, item)
        elif v >= parse_version("4.7"):
            self._add(e, e["cves"][0], item, "backport for your branch: see wordpress.org (not verified)", "verify",
                      "In the affected range (4.7.0 - 7.1.3). Update to the newest release for your branch, "
                      "or to 7.1.4.")  # fmt: skip
        if item.extra.get("upgrade_dir_present"):
            self._add(e, e["cves"][0], item, "n/a", "verify",
                      "wp-content/upgrade exists. Remove leftovers and deny web access to it "
                      "(`iisguard fix wp-upgrade-dir`, M4).")  # fmt: skip

    def _dotnet(self, item: Item) -> None:
        name = str(item.extra.get("runtime_name", "Microsoft.AspNetCore.App"))
        if name not in ("Microsoft.AspNetCore.App", "Microsoft.NETCore.App"):
            return
        e = self.entries["dotnet-decompression-dos"]
        self._branch_check(e, item, eol_below=parse_version("8.0"))
        if name == "Microsoft.AspNetCore.App":
            self._manual("aspnetcore-oct2026-manual", item)

    def _windows(self, item: Item) -> None:
        try:
            v = parse_version(item.version)
        except VersionError:
            return
        family = str(item.extra.get("family", "any"))
        prefix = ".".join(str(n) for n in v.nums[:3])
        rows = [r for r in self.known["windows_builds"] if r["prefix"] == prefix and r["family"] in (family, "any")]
        for key in ("windows-httpsys", "windows-iis-eop"):
            e = self.entries[key]
            for cve in e["cves"]:
                if not rows:
                    self._add(e, cve, item, "no fixed build listed in NVD; check MSRC", "verify")
                    continue
                r = rows[0]
                ok = v >= parse_version(str(r["fixed"]))
                self._add(e, cve, item, str(r["fixed"]), "ok" if ok else "vulnerable")

    def _sharepoint(self, item: Item) -> None:
        e = self.entries["sharepoint-se-signature"]
        try:
            v = parse_version(item.version)
        except VersionError:
            return
        for cve in e["cves"]:
            if len(v.nums) >= 3 and v.nums[0] == 16 and v.nums[2] >= 14326:  # Subscription Edition builds
                fixed = str(e["fixed_build_se"])
                self._add(e, cve, item, fixed, "ok" if v >= parse_version(fixed) else "vulnerable")
            else:
                self._add(e, cve, item, "not published for 2016/2019 in NVD; check MSRC", "manual")

    def run(self, items: list[Item]) -> list[Finding]:
        handlers = {
            "php": self._php, "wordpress": self._wordpress, "dotnet-runtime": self._dotnet,
            "windows": self._windows, "sharepoint": self._sharepoint,
        }  # fmt: skip
        for item in items:
            if item.product in handlers:
                handlers[item.product](item)
            elif item.product == "exchange":
                self._manual("exchange-oct2026-manual", item)
        self.findings.sort(key=lambda f: (STATUS_ORDER.index(f.status), f.product, f.cve))
        return self.findings

    # ------------------------------------------------------------------ KEV watch
    _KEV_PATTERNS = {
        "php": r"\bPHP\b", "wordpress": r"WordPress", "sharepoint": r"SharePoint", "exchange": r"Exchange",
        "iis": r"Internet Information|IIS", "nginx": r"nginx", "apache": r"HTTP Server|Tomcat",
        "dotnet-runtime": r"^Microsoft .*(\.NET|ASP\.NET)",
    }  # fmt: skip

    def kev_watch(self, items: list[Item], limit: int = 8, months: int = 12) -> list[dict[str, str]]:
        """Recent KEV entries for products that are present but have no verified version rule (verify manually)."""
        if not self.kev:
            return []
        covered = {f.cve for f in self.findings}
        cutoff = (
            (date.fromisoformat(self.kev.date_released[:10]) - timedelta(days=30 * months)).isoformat()
            if self.kev.date_released
            else ""
        )
        out: list[dict[str, str]] = []
        for product in sorted({i.product for i in items}):
            pat = self._KEV_PATTERNS.get(product)
            if not pat:
                continue
            vers = sorted({i.version for i in items if i.product == product})
            found = ", ".join(vers[:3]) + (f" (+{len(vers) - 3} more)" if len(vers) > 3 else "")
            hits = [
                k
                for k in self.kev.for_product(pat)
                if k["cveID"] not in covered and str(k.get("dateAdded", "")) >= cutoff
            ]
            for k in sorted(hits, key=lambda k: str(k.get("dateAdded", "")), reverse=True)[:limit]:
                out.append(
                    {
                        "cve": k["cveID"],
                        "product": product,
                        "found": found,
                        "kev_due": str(k.get("dueDate", "")),
                        "name": str(k.get("vulnerabilityName", "")),
                        "action": "Verify your version against the vendor advisory.",
                    }
                )
        return out


def render_table(findings: list[Finding], show_ok: bool = False) -> str:
    rows = [f for f in findings if show_ok or f.status != "ok"]
    head = ("STATUS", "CVE", "PRODUCT", "FOUND", "FIXED", "KEV DUE", "ACTION")
    body = [
        (f.status.upper(), f.cve, f.product, f.found, f.fixed, f.kev_due or "-", re.sub(r"\s+", " ", f.action)[:90])
        for f in rows
    ]
    if not body:
        return "No findings."
    widths = [max(len(r[i]) for r in [head, *body]) for i in range(6)]
    widths[4] = min(widths[4], 44)
    lines = []
    for r in [head, *body]:
        cells = [r[i][: widths[i]].ljust(widths[i]) for i in range(6)]
        lines.append("  ".join(cells) + "  " + r[6])
    return "\n".join(lines)
