"""CISA Known Exploited Vulnerabilities (KEV): download, cache, offline snapshot, web-facing filter.

Feed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (JSON feed URL below).
Order of preference: fresh cache (<24 h) -> download -> stale cache -> bundled snapshot.
With ``offline=True`` the network is never touched.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_MAX_AGE = 24 * 3600

# Vendor/product text that makes an entry "web-facing" for our purposes.
_WEB_RX = re.compile(
    r"\bphp\b|wordpress|drupal|joomla|\biis\b|internet information|asp\.net|\.net\b|sharepoint|exchange server|"
    r"microsoft exchange|apache|nginx|tomcat|citrix|netscaler|ivanti|sonicwall|palo alto|pan-os|beyondtrust|"
    r"gitlab|plex|http\.sys",
    re.IGNORECASE,
)
_KEEP = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate",
         "shortDescription", "knownRansomwareCampaignUse", "notes")  # fmt: skip


class KevError(RuntimeError):
    pass


@dataclass
class Kev:
    catalog_version: str = ""
    date_released: str = ""
    source: str = ""  # network | cache | stale-cache | snapshot
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get(self, cve: str) -> dict[str, Any] | None:
        return self.entries.get(cve.upper())

    def for_product(self, pattern: str) -> list[dict[str, Any]]:
        rx = re.compile(pattern, re.IGNORECASE)
        return [e for e in self.entries.values() if rx.search(f"{e['vendorProject']} {e['product']}")]


def is_web_facing(entry: dict[str, Any]) -> bool:
    text = f"{entry.get('vendorProject', '')} {entry.get('product', '')} {entry.get('vulnerabilityName', '')}"
    return bool(_WEB_RX.search(text))


def _validate(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise KevError("not a KEV catalog (missing 'vulnerabilities')")
    for v in data["vulnerabilities"]:
        if not isinstance(v, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(v.get("cveID", ""))):
            raise KevError("malformed KEV entry")
    return data


def build_snapshot(raw: dict[str, Any]) -> dict[str, Any]:
    """Reduce a full catalog to the web-facing subset we bundle for --offline use."""
    _validate(raw)
    vulns = [{k: v[k] for k in _KEEP if k in v} for v in raw["vulnerabilities"] if is_web_facing(v)]
    return {
        "title": raw.get("title", "CISA KEV (web-facing subset)"),
        "catalogVersion": raw.get("catalogVersion", ""),
        "dateReleased": raw.get("dateReleased", ""),
        "count": len(vulns),
        "vulnerabilities": vulns,
    }


def _to_kev(data: dict[str, Any], source: str, web_only: bool = True) -> Kev:
    entries = {v["cveID"].upper(): v for v in data["vulnerabilities"] if (not web_only) or is_web_facing(v)}
    return Kev(str(data.get("catalogVersion", "")), str(data.get("dateReleased", "")), source, entries)


def default_cache_dir() -> Path:
    from iisguard.state import state_dir

    return state_dir() / "cache"


def _download(url: str, timeout: int = 30) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "iisguard (+https://github.com/qmmughal/iisguard)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https URL
        return _validate(json.loads(r.read().decode("utf-8")))


def bundled_snapshot() -> dict[str, Any]:
    text = resources.files("iisguard.audit").joinpath("data/kev_snapshot.json").read_text(encoding="utf-8")
    return _validate(json.loads(text))


def load_kev(
    offline: bool = False,
    cache_dir: Path | None = None,
    fetch: Callable[[str], dict[str, Any]] = _download,
    now: float | None = None,
) -> Kev:
    cache = (cache_dir or default_cache_dir()) / "kev.json"
    now = time.time() if now is None else now
    cached: dict[str, Any] | None = None
    fresh = False
    if cache.is_file():
        try:
            cached = _validate(json.loads(cache.read_text(encoding="utf-8")))
            fresh = now - cache.stat().st_mtime < CACHE_MAX_AGE
        except (OSError, ValueError, KevError):
            cached = None
    if cached is not None and (fresh or offline):
        return _to_kev(cached, "cache" if fresh else "stale-cache")
    if not offline:
        try:
            data = fetch(KEV_URL)
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                tmp = cache.with_suffix(".tmp")
                tmp.write_text(json.dumps(data), encoding="utf-8")
                tmp.replace(cache)
            except OSError:
                pass  # cache is best-effort
            return _to_kev(data, "network")
        except (OSError, ValueError, KevError):
            if cached is not None:
                return _to_kev(cached, "stale-cache")
    return _to_kev(bundled_snapshot(), "snapshot", web_only=False)
