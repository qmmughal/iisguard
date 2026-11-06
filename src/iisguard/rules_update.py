"""update-rules: fetch a newer rule pack (and CDN ranges) into the state dir, validating before installing.

Integrity note: the pack index lists a SHA-256 for each file, which catches corruption and partial downloads. It
does NOT authenticate the publisher (index and files come from the same origin over HTTPS). Review diffs of
important updates, or pin your own copy with `rules_path` in the config.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from collections.abc import Callable
from importlib import resources
from pathlib import Path

from iisguard.rules import RuleError, load_rules, sample_matches
from iisguard.state import read_json, state_dir, write_json

INDEX_URL = "https://raw.githubusercontent.com/qmmughal/iisguard/main/rule-packs/index.json"
CLOUDFLARE_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
CLOUDFRONT_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
PACK_NAME = re.compile(r"^[a-z0-9][a-z0-9\-]{0,40}$")
MAX_BYTES = 5 * 1024 * 1024

Fetch = Callable[[str], bytes]


class UpdateError(RuntimeError):
    pass


def fetch_url(url: str) -> bytes:
    if not url.startswith("https://"):
        raise UpdateError("only https:// URLs are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": "iisguard-update (+https://github.com/qmmughal/iisguard)"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - https enforced above
        data: bytes = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise UpdateError(f"{url}: response too large")
    return data


def bundled_version() -> str:
    return resources.files("iisguard.rules").joinpath("VERSION").read_text(encoding="utf-8").strip()


def user_pack_path(state: Path | None = None) -> Path:
    return (state or state_dir()) / "rules" / "web-core" / "rules.yaml"


def installed_version(state: Path | None = None) -> str:
    return str(read_json((state or state_dir()) / "rules" / "installed.json", {}).get("web-core", ""))


def validate_pack(path: Path) -> int:
    """Load the pack AND run every rule's own match / no_match tests. Raises RuleError on any failure."""
    rules = load_rules(str(path))
    for r in rules:
        for sample in r.tests_match:
            if not sample_matches(r, sample):
                raise RuleError(f"rule {r.id}: should match {sample!r}")
        for sample in r.tests_no_match:
            if sample_matches(r, sample):
                raise RuleError(f"rule {r.id}: must NOT match {sample!r}")
    return len(rules)


def update_rules(
    index_url: str = INDEX_URL, fetch: Fetch | None = None, state: Path | None = None, check_only: bool = False
) -> list[str]:
    fetch = fetch if fetch is not None else fetch_url  # resolved at call time so it can be substituted
    st = state or state_dir()
    msgs: list[str] = []
    try:
        index = json.loads(fetch(index_url).decode("utf-8"))
    except (OSError, ValueError) as e:
        raise UpdateError(f"could not read the pack index: {e}") from e
    if index.get("schema") != 1 or not isinstance(index.get("packs"), list):
        raise UpdateError("unsupported index format")
    base = index_url.rsplit("/", 1)[0] + "/"
    current = installed_version(st) or bundled_version()
    for pack in index["packs"]:
        name, version, rel, want = (
            str(pack["name"]),
            str(pack["version"]),
            str(pack["file"]),
            str(pack["sha256"]).lower(),
        )
        if not PACK_NAME.match(name) or ".." in rel or rel.startswith(("/", "\\")):
            raise UpdateError(f"unsafe pack entry {name!r}")
        if name != "web-core":
            msgs.append(f"skipped unknown pack {name}")
            continue
        if version <= current:
            msgs.append(f"{name}: already up to date ({current})")
            continue
        if check_only:
            msgs.append(f"{name}: update available {current} -> {version}")
            continue
        data = fetch(base + rel)
        if hashlib.sha256(data).hexdigest() != want:
            raise UpdateError(f"{name}: SHA-256 mismatch; nothing installed")
        dest = user_pack_path(st)
        tmp = dest.with_suffix(".new")
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        try:
            n = validate_pack(tmp)
        except RuleError as e:
            tmp.unlink(missing_ok=True)
            raise UpdateError(f"{name}: pack failed validation, not installed: {e}") from e
        if dest.exists():
            dest.with_suffix(".previous").write_bytes(dest.read_bytes())
        tmp.replace(dest)
        inst = read_json(st / "rules" / "installed.json", {})
        inst[name] = version
        write_json(st / "rules" / "installed.json", inst)
        msgs.append(f"{name}: installed {version} ({n} rules validated); previous copy kept as rules.previous")
    return msgs


def update_cdn(fetch: Fetch | None = None, state: Path | None = None) -> list[str]:
    """Refresh Cloudflare and CloudFront ranges. Azure Front Door has no stable URL, so add it to `cdn_ranges` by hand."""
    import ipaddress

    fetch = fetch if fetch is not None else fetch_url
    st = state or state_dir()
    providers: dict[str, list[str]] = {}
    cf: list[str] = []
    for u in CLOUDFLARE_URLS:
        cf += [ln.strip() for ln in fetch(u).decode().splitlines() if ln.strip()]
    providers["cloudflare"] = cf
    data = json.loads(fetch(CLOUDFRONT_URL).decode())
    aws = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]
    aws += [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", []) if p.get("service") == "CLOUDFRONT"]
    providers["cloudfront"] = aws
    for name, ranges in providers.items():
        if not ranges:
            raise UpdateError(f"{name}: empty range list; keeping the existing one")
        for r in ranges:
            ipaddress.ip_network(r)  # raises on garbage
    write_json(st / "cdn_ranges.json", {"snapshot": "updated", "providers": providers})
    return [f"{k}: {len(v)} ranges" for k, v in providers.items()]
