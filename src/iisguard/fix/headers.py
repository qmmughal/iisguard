"""Security response headers. IIS: edits web.config. nginx / Apache: prints a snippet (you paste it)."""

from __future__ import annotations

from pathlib import Path

from iisguard.fix.base import Change, FixPlan, eol, read_text
from iisguard.fix.xmledit import has, insert, new_config, validate

HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "SAMEORIGIN"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
]
HSTS = ("Strict-Transport-Security", "max-age=31536000")  # only with --hsts: breaks sites that still need plain HTTP


def snippets(hsts: bool) -> dict[str, str]:
    hs = HEADERS + ([HSTS] if hsts else [])
    return {
        "nginx": "\n".join(f'add_header {n} "{v}" always;' for n, v in hs),
        "apache": "\n".join(f'Header always set {n} "{v}"' for n, v in hs),
    }


def plan(web_config: str, hsts: bool = False) -> FixPlan:
    p = Path(web_config)
    if p.is_dir():
        p = p / "web.config"
    hs = HEADERS + ([HSTS] if hsts else [])
    fp = FixPlan("headers", snippets=snippets(hsts))
    old = read_text(p) if p.exists() else None
    text = old if old is not None else ""
    nl = eol(text)
    added = []
    for name, value in hs:
        if has(text, rf'name\s*=\s*"{name}"'):
            continue
        frag = f'<add name="{name}" value="{value}" />'
        text = insert(text, ["system.webServer", "httpProtocol", "customHeaders"], frag) if text else new_config(
            f"  <system.webServer>{nl}    <httpProtocol>{nl}      <customHeaders>{nl}        {frag}{nl}      </customHeaders>{nl}"
            f"    </httpProtocol>{nl}  </system.webServer>{nl}", nl)  # fmt: skip
        added.append(name)
    if not has(text, r'<remove\s+name\s*=\s*"X-Powered-By"'):
        text = insert(text, ["system.webServer", "httpProtocol", "customHeaders"], '<remove name="X-Powered-By" />')
        added.append("remove X-Powered-By")
    if added:
        validate(text)
        fp.changes.append(Change(p, text, "add: " + ", ".join(added), old))
    else:
        fp.notes.append("All headers are already present.")
    fp.notes.append(
        "Test the site afterwards: X-Frame-Options SAMEORIGIN breaks pages that must be framed by other sites."
    )
    return fp
