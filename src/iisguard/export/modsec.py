"""ModSecurity v2/v3 / Coraza rules (SecRule). Complements OWASP CRS: IDs are in a private range, not CRS's."""

from __future__ import annotations

from iisguard.models import Rule

ID_BASE = 9877000  # inside CRS's 9,000,000-9,999,999 third-party range; change with --id-base on collisions
VAR = {"path": "REQUEST_FILENAME", "query": "QUERY_STRING", "uri": "REQUEST_URI", "ua": "REQUEST_HEADERS:User-Agent"}
SEVERITY = {"critical": "CRITICAL", "high": "ERROR", "medium": "WARNING", "low": "NOTICE", "info": "INFO"}
CRS_SCORE = {"critical": "critical", "high": "error", "medium": "warning", "low": "notice", "info": "notice"}
MODES = ("detect", "block", "crs")


def esc(s: str) -> str:
    return s.replace('"', '\\"')


def clean_msg(s: str) -> str:
    return s.replace("'", "").replace('"', "").replace("\\", "")[:120]


def actions(rule: Rule, rid: int, mode: str, chained: bool) -> str:
    tags = f"tag:'iisguard',tag:'iisguard/{rule.category}'" + "".join(
        f",tag:'{c}'" for c in rule.cve if c.startswith("CVE-")
    )
    base = f"id:{rid},phase:2,t:none,t:urlDecodeUni,msg:'iisguard {rule.id}: {clean_msg(rule.description or rule.id)}',{tags}"
    if chained:
        return base + ",chain"
    sev = SEVERITY[rule.severity]
    if mode == "block":
        tail = f"deny,status:403,log,auditlog,severity:'{sev}'"
    elif mode == "crs":
        tail = (f"pass,log,auditlog,severity:'{sev}',"
                f"setvar:'tx.inbound_anomaly_score_pl1=+%{{tx.{CRS_SCORE[rule.severity]}_anomaly_score}}'")  # fmt: skip
    else:
        tail = f"pass,log,auditlog,severity:'{sev}'"
    return f"{base},{tail}"


def one(rule: Rule, rid: int, mode: str) -> str:
    """One SecRule, or a chain when the rule has a method filter and/or an exclusion."""
    var = VAR[rule.field]
    pat = esc("(?i)" + rule.pattern)
    links: list[str] = []
    if rule.methods:
        links.append(f'SecRule REQUEST_METHOD "@rx ^({"|".join(rule.methods)})$"')
    links.append(f'SecRule {var} "@rx {pat}"')
    if rule.exclude:
        links.append(f'SecRule {var} "!@rx {esc("(?i)" + rule.exclude)}"')
    if len(links) == 1:
        return f'{links[0]} "{actions(rule, rid, mode, False)}"\n'
    lines = [f'{links[0]} "{actions(rule, rid, mode, True)}"']
    for i, link in enumerate(links[1:], 1):
        tail = "t:none,t:urlDecodeUni" + (",chain" if i < len(links) - 1 else "")
        lines.append(f'    {link} "{tail}"')
    return "\n".join(lines) + "\n"


def php_upload_progress(rid: int, mode: str) -> str:
    r = Rule("php2shell-upload-progress-body", "php2shell", 100, "critical", "uri", "", "PHP_SESSION_UPLOAD_PROGRESS in request data",
             ["CVE-2026-109619", "CVE-2026-115560"])  # fmt: skip
    head = 'SecRule ARGS_NAMES|ARGS|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_URI "@contains PHP_SESSION_UPLOAD_PROGRESS" '
    return head + f'"{actions(r, rid, mode, False)}"\n'


def export(rules: list[Rule], mode: str = "detect", min_score: int = 10, id_base: int = ID_BASE) -> str:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    out = [
        "# iisguard ModSecurity rules (generated). Load AFTER the OWASP CRS or standalone.",
        f"# Mode: {mode}. 'detect' logs only; 'block' returns 403; 'crs' adds to the CRS inbound anomaly score.",
        "# Use `SecRuleEngine DetectionOnly` first and review the audit log before enforcing.",
        "",
    ]
    n = 0
    for r in rules:
        if r.enabled and r.field in VAR and r.score >= min_score:
            out.append(one(r, id_base + n, mode))
            n += 1
    out.append("# PHP upload-progress marker in any request data (PHP2Shell vector; see docs)")
    out.append(php_upload_progress(id_base + 900, mode))
    return "\n".join(out)
