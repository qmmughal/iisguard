"""Sigma rules (one YAML document per detection rule) for web-server logs."""

from __future__ import annotations

import uuid
from datetime import date

from iisguard.export import nvd_url, rule_cves
from iisguard.models import Rule

NS = uuid.UUID("6f1d3a52-9b1c-4c0e-8f6e-0a1b2c3d4e5f")  # fixed namespace: ids are stable across runs
FIELD_MAP = {"path": "c-uri-stem", "query": "c-uri-query", "uri": "c-uri", "ua": "c-useragent", "method": "cs-method"}
LEVEL = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "informational"}
ATTACK = {
    "webshell": ["attack.persistence", "attack.t1505.003"],
    "php2shell": ["attack.initial_access", "attack.t1190"],
    "wordpress": ["attack.initial_access", "attack.t1190"],
    "viewstate": ["attack.initial_access", "attack.t1190"],
    "exploit": ["attack.initial_access", "attack.t1190"],
    "sharepoint": ["attack.initial_access", "attack.t1190"],
    "exchange": ["attack.initial_access", "attack.t1190"],
    "recon": ["attack.reconnaissance", "attack.t1595"],
    "scanner": ["attack.reconnaissance", "attack.t1595"],
}


def q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def one(rule: Rule, when: str) -> str:
    sel: list[str] = []
    if rule.methods:
        sel.append(f"    cs-method: {rule.methods[0]}" if len(rule.methods) == 1 else
                   "    cs-method:\n" + "\n".join(f"      - {m}" for m in rule.methods))  # fmt: skip
    sel.append(f"    {FIELD_MAP[rule.field]}|re: {q('(?i)' + rule.pattern)}")
    filt = f"\n  filter_known:\n    {FIELD_MAP[rule.field]}|re: {q('(?i)' + rule.exclude)}" if rule.exclude else ""
    tags = list(ATTACK.get(rule.category, [])) + [f"cve.{c[4:].replace('-', '.')}" for c in rule_cves(rule)]
    refs = [nvd_url(c) for c in rule_cves(rule)]
    lines = [
        f"title: iisguard - {rule.id}",
        f"id: {uuid.uuid5(NS, rule.id)}",
        "status: experimental",
        f"description: {q(rule.description or rule.id)}",
    ]
    if refs:
        lines += ["references:", *[f"  - {r}" for r in refs]]
    lines += [
        "author: iisguard contributors",
        f"date: {when}",
        "tags:" if tags else "tags: []",
        *[f"  - {t}" for t in tags],
    ]
    lines += [
        "logsource:\n  category: webserver",
        "detection:\n  selection:\n" + "\n".join(sel) + filt,
        "  condition: selection and not filter_known" if rule.exclude else "  condition: selection",
        "falsepositives:\n  - See docs/false-positives.md; tune per site",
        f"level: {LEVEL[rule.severity]}",
    ]
    return "\n".join(lines) + "\n"


def export(rules: list[Rule], min_score: int = 10, when: str | None = None) -> str:
    when = when or date.today().strftime("%Y-%m-%d")
    docs = [one(r, when) for r in rules if r.enabled and r.field in FIELD_MAP and r.score >= min_score]
    return "---\n".join(docs)
