"""CrowdSec scenarios (leaky/trigger buckets over HTTP logs) and a decisions blocklist.

CrowdSec filters use Go RE2, so rules that need lookaround are skipped (and listed in a comment). Load the output
into /etc/crowdsec/scenarios/ and run `cscli hub` / `systemctl reload crowdsec`. Not exercised against a live
CrowdSec by the author's CI: validate with `cscli scenarios inspect` after installing.
"""

from __future__ import annotations

from iisguard.config import Config
from iisguard.export import re2_compatible
from iisguard.models import Rule

VARS = {
    "path": "evt.Meta.http_path",
    "uri": "evt.Meta.http_path",
    "query": "evt.Meta.http_path",
    "ua": "evt.Meta.http_user_agent",
}
LOGS = "evt.Meta.log_type in ['http_access-log', 'http_error-log']"
BUCKET = {"critical": ("trigger", 0), "high": ("leaky", 2), "medium": ("leaky", 5), "low": ("leaky", 10)}


def scenario(
    name: str, desc: str, filt: str, kind: str, cap: int, leak: str, label: str, behavior: str, black: str = "10m"
) -> str:
    lines = [
        f"type: {kind}",
        f"name: iisguard/{name}",
        f'description: "{desc.replace(chr(34), chr(39))[:150]}"',
        "filter: |",
        f"  {filt}",
        "groupby: evt.Meta.source_ip",
    ]
    if kind == "leaky":
        lines += [f"capacity: {cap}", f"leakspeed: {leak}"]
    lines += [
        f"blackhole: {black}",
        "labels:",
        "  service: http",
        f"  type: {label}",
        "  remediation: true",
        f"  behavior: {behavior}",
        "  spoofable: 0",
        "  confidence: 3",
    ]
    return "\n".join(lines) + "\n"


def export(rules: list[Rule], cfg: Config | None = None, min_score: int = 40) -> tuple[str, list[str]]:
    cfg = cfg or Config()
    docs: list[str] = []
    skipped: list[str] = []
    for r in rules:
        if not r.enabled or r.field not in VARS or r.score < min_score:
            continue
        if not re2_compatible(r.pattern) or "`" in r.pattern:
            skipped.append(r.id)
            continue
        kind, cap = BUCKET.get(r.severity, ("leaky", 10))
        cond = f"{VARS[r.field]} matches `(?i){r.pattern}`"
        if r.exclude:
            if not re2_compatible(r.exclude) or "`" in r.exclude:
                skipped.append(r.id)
                continue
            cond += f" && !({VARS[r.field]} matches `(?i){r.exclude}`)"
        if r.methods:
            cond = f"evt.Meta.http_verb in [{', '.join(repr(m) for m in r.methods)}] && " + cond
        label = "scan" if r.category in ("recon", "scanner") else "exploit"
        docs.append(
            scenario(r.id, r.description or r.id, f"{LOGS} && {cond}", kind, cap, "60s", label, f"http:{label}")
        )
    login = "|".join(p.replace("`", "") for p in cfg.login_paths)
    docs.append(
        scenario(
            "login-bruteforce",
            "Many login POSTs from one IP",
            f"{LOGS} && evt.Meta.http_verb == 'POST' && evt.Meta.http_path matches `(?i)^(?:{login})/?(?:\\?.*)?$`",
            "leaky",
            cfg.brute_attempts,
            f"{cfg.spray_window // cfg.brute_attempts}s",
            "bruteforce",
            "http:bruteforce",
        )
    )
    return "---\n".join(docs), skipped


def blocklist(ips: list[str]) -> str:
    """One IP per line: `cscli decisions import -i FILE --format values --duration 24h --reason iisguard`."""
    return "\n".join(ips) + ("\n" if ips else "")
