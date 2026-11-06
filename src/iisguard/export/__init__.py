"""Export detections as Sigma, YARA, CrowdSec and ModSecurity rules, and IP lists. Generated from the rule packs."""

from __future__ import annotations

import re

from iisguard.models import Rule

LOOKAROUND = re.compile(r"\(\?(?:=|!|<=|<!)|\\[1-9]|\(\?P?<[A-Za-z]|\(\?>")
CVE_RX = re.compile(r"^CVE-\d{4}-\d{4,}$")


def re2_compatible(pattern: str) -> bool:
    """RE2 (CrowdSec/Go) and the YARA engines have no lookaround or backreferences."""
    return LOOKAROUND.search(pattern) is None


def nvd_url(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def rule_cves(rule: Rule) -> list[str]:
    return [c for c in rule.cve if CVE_RX.match(c)]
