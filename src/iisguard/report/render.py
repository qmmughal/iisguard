"""CSV, JSON, single-file offline HTML (dark/light) and SARIF 2.1.0 renderers."""

from __future__ import annotations

import csv
import html
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from iisguard import __version__
from iisguard.report.model import Finding

FORMATS = ("csv", "json", "html", "sarif")
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SEV_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d4ed8", "info": "#4b5563"}


def _csv_safe(v: str) -> str:
    """Neutralize spreadsheet formula injection (cells that start with = + - @)."""
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["source", "severity", "title", "location", "detail", "rule", "cve"])
    for f in findings:
        w.writerow(
            [_csv_safe(x) for x in (f.source, f.severity, f.title, f.location, f.detail, f.rule, ";".join(f.cve))]
        )
    return buf.getvalue()


def to_json(findings: list[Finding]) -> str:
    return json.dumps(
        {"tool": f"iisguard {__version__}", "count": len(findings), "findings": [f.to_dict() for f in findings]},
        indent=2,
    )


def _uri(loc: str) -> str | None:
    """file:// URI for absolute paths (Windows drive, UNC or POSIX); None for non-file locations."""
    from urllib.parse import quote

    if re.match(r"^[A-Za-z]:[\\/]", loc):
        return "file:///" + quote(loc.replace("\\", "/"), safe="/:")
    if loc.startswith("\\\\"):
        return "file:" + quote(loc.replace("\\", "/"), safe="/:")
    if loc.startswith("/"):
        return "file://" + quote(loc, safe="/:")
    return None


def to_sarif(findings: list[Finding]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        rid = f.rule or f"{f.source}/{f.title[:40]}"
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": f.title[:120]},
                               "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]}})  # fmt: skip
        res: dict[str, Any] = {"ruleId": rid, "level": SARIF_LEVEL[f.severity],
                               "message": {"text": (f.title + (": " + f.detail if f.detail else ""))[:900]}}  # fmt: skip
        uri = _uri(f.location)
        if uri:
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        elif f.location:
            res["locations"] = [{"logicalLocations": [{"name": f.location}]}]
        res["properties"] = {"severity": f.severity, "source": f.source, "cve": f.cve}
        results.append(res)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "iisguard", "version": __version__, "informationUri": "https://github.com/qmmughal/iisguard",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }  # fmt: skip
    return json.dumps(doc, indent=2)


_CSS = """
:root{--bg:#f8fafc;--fg:#0f172a;--mut:#475569;--card:#fff;--line:#e2e8f0}
:root[data-theme=dark]{--bg:#0b1220;--fg:#e5e7eb;--mut:#94a3b8;--card:#111827;--line:#1f2937}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0b1220;--fg:#e5e7eb;--mut:#94a3b8;--card:#111827;--line:#1f2937}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}h1{font-size:20px;margin:8px 0}.mut{color:var(--mut)}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}
input,select,button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 10px;font:inherit}
.cards{display:flex;gap:8px;flex-wrap:wrap}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 14px;min-width:90px}
.card b{display:block;font-size:20px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{font-size:12px;text-transform:uppercase;color:var(--mut)}.sev{color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600}
@media (max-width:640px){th:nth-child(5),td:nth-child(5){display:none}}
"""
_JS = """
const q=document.getElementById('q'),s=document.getElementById('s'),rows=[...document.querySelectorAll('tbody tr')];
function f(){const t=q.value.toLowerCase(),v=s.value;let n=0;rows.forEach(r=>{const ok=(!v||r.dataset.sev===v)&&r.textContent.toLowerCase().includes(t);r.hidden=!ok;if(ok)n++});document.getElementById('n').textContent=n}
q.oninput=s.onchange=f;
document.getElementById('theme').onclick=()=>{const d=document.documentElement;const dark=getComputedStyle(d).getPropertyValue('--bg').trim()==='#0b1220';d.dataset.theme=dark?'light':'dark'};
"""


def to_html(findings: list[Finding], title: str = "iisguard report") -> str:
    e = html.escape
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_COLOR}
    cards = "".join(f'<div class="card"><b>{counts[s]}</b><span class="mut">{s}</span></div>' for s in SEV_COLOR)
    rows = "".join(
        f'<tr data-sev="{e(f.severity)}"><td><span class="sev" style="background:{SEV_COLOR[f.severity]}">{e(f.severity)}</span></td>'
        f"<td>{e(f.source)}</td><td>{e(f.title)}</td><td>{e(f.location)}</td><td>{e(f.detail)}</td></tr>"
        for f in findings
    )
    when = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'\">"
        f"<title>{e(title)}</title><style>{_CSS}</style></head><body><main>"
        f'<h1>{e(title)}</h1><div class="mut">iisguard {__version__} · {when} · <span id="n">{len(findings)}</span> finding(s) shown</div>'
        f'<div class="cards" style="margin-top:12px">{cards}</div>'
        '<div class="bar"><input id="q" placeholder="Filter text" aria-label="Filter text"><select id="s" aria-label="Severity">'
        '<option value="">all severities</option>' + "".join(f"<option>{s}</option>" for s in SEV_COLOR) + "</select>"
        '<button id="theme" type="button">Dark/Light</button></div>'
        "<table><thead><tr><th>Severity</th><th>Source</th><th>Finding</th><th>Location</th><th>Detail</th></tr></thead>"
        f'<tbody>{rows}</tbody></table><p class="mut">Secrets are masked. Generated offline; no external resources.</p>'
        f"</main><script>{_JS}</script></body></html>"
    )


def render(findings: list[Finding], fmt: str) -> str:
    if fmt == "csv":
        return to_csv(findings)
    if fmt == "json":
        return to_json(findings)
    if fmt == "html":
        return to_html(findings)
    if fmt == "sarif":
        return to_sarif(findings)
    raise ValueError(f"format must be one of {FORMATS}")


def write(findings: list[Finding], fmt: str, out: str | None) -> None:
    text = render(findings, fmt)
    if out:
        Path(out).write_text(text, encoding="utf-8", newline="\n")
    else:
        print(text)
