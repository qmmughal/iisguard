"""One normalized finding type, built from the JSON output of scan / audit / hunt / exposure."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from iisguard.models import SEVERITY_RANK


@dataclass
class Finding:
    source: str  # scan | audit | hunt | exposure
    severity: str
    title: str
    location: str = ""
    detail: str = ""
    rule: str = ""
    cve: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sev(s: Any) -> str:
    return s if s in SEVERITY_RANK else "info"


def from_document(doc: dict[str, Any]) -> list[Finding]:
    """Recognize the JSON written by `scan`, `audit`, `hunt` or `exposure` (--output-format json)."""
    out: list[Finding] = []
    if "detections" in doc:  # scan
        for d in doc["detections"]:
            out.append(Finding("scan", _sev(d["severity"]), f"{d['rule_id']} from {d['ip']} ({d['count']}x)", d["ip"],
                               "; ".join(d.get("samples", []))[:300], d["rule_id"], d.get("cve", [])))  # fmt: skip
        for h in doc.get("host_findings", []):
            out.append(Finding("scan", _sev(h["severity"]), h["id"], "", h.get("detail", ""), h["id"]))
        for b in doc.get("blocks", []):
            out.append(
                Finding(
                    "scan",
                    "high",
                    f"would block {b['ip']} (score {b['score']})",
                    b["ip"],
                    ", ".join(b.get("rules", [])),
                )
            )
    if "findings" in doc and "inventory" in doc:  # audit
        sev = {"vulnerable": "high", "eol": "high", "config": "medium", "verify": "low", "manual": "low", "ok": "info"}
        for f in doc["findings"]:
            if f["status"] == "ok":
                continue
            detail = f"found {f['found']}, fixed {f['fixed']}" + (
                f", KEV due {f['kev_due']}" if f.get("kev_due") else ""
            )
            out.append(Finding("audit", "critical" if f["status"] == "vulnerable" and f.get("in_kev") else sev[f["status"]],
                               f"{f['cve']} {f['product']} [{f['status']}]", f.get("location", ""), detail, f["cve"], [f["cve"]]))  # fmt: skip
    for f in doc.get("files", []) if isinstance(doc.get("files"), list) else []:  # hunt: files
        out.append(
            Finding(
                "hunt",
                _sev(f["severity"]),
                f"suspicious file (score {f['score']})",
                f["path"],
                "; ".join(f["reasons"]),
                "file-hunter",
            )
        )
    for f in doc.get("secrets", []) if isinstance(doc.get("secrets"), list) else []:
        out.append(
            Finding("hunt", _sev(f["severity"]), f"secret/exposed file: {f['id']}", f["path"], f["detail"], f["id"])
        )
    wc = doc.get("webconfig")
    if isinstance(wc, dict):
        for f in wc.get("findings", []):
            out.append(Finding("hunt", _sev(f["severity"]), f"web.config: {f['id']}", f["path"], f["detail"], f["id"]))
    pr = doc.get("processes")
    if isinstance(pr, dict):
        for f in pr.get("findings", []):
            out.append(
                Finding("hunt", _sev(f["severity"]), f"{f['parent']} spawned {f['child']}", "", f["cmdline"], f["rule"])
            )
    ex = doc.get("exposure")
    if isinstance(ex, dict):
        for f in ex.get("findings", []):
            out.append(
                Finding(
                    "exposure",
                    _sev(f["severity"]),
                    f["title"],
                    f.get("location", ""),
                    f.get("detail", ""),
                    f.get("rule", ""),
                )
            )
    out.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.source, f.title))
    return out
