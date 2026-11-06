"""Report renderers. M1 ships text and JSON; CSV / HTML / SARIF arrive in M5."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from iisguard.analyzer import Report


def _t(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%S") if ts > 0 else "-"


def render_json(rep: Report) -> str:
    return json.dumps(rep.to_dict(), indent=2, sort_keys=True)


def render_text(rep: Report, top: int = 30) -> str:
    out: list[str] = []
    s = rep.stats
    out.append(
        f"Scanned {s.get('events', 0)} events from {s.get('files', 0)} file(s); "
        f"{s.get('bad_lines', 0)} unparseable lines. Highest severity: {rep.max_severity}."
    )
    if rep.host_findings:
        out.append("\nHost-level findings")
        for f in rep.host_findings:
            out.append(f"  [{f['severity']:<8}] {f['id']}: {f['detail']} ({_t(f['first_ts'])})")
    if rep.hits:
        out.append(f"\nDetections (top {top} by severity)")
        out.append(f"  {'severity':<9} {'ip':<40} {'rule':<28} {'count':>5}  sample")
        for h in rep.hits[:top]:
            sample = h.samples[0] if h.samples else ""
            out.append(f"  {h.severity:<9} {h.ip:<40} {h.rule_id:<28} {h.count:>5}  {sample[:60]}")
        if len(rep.hits) > top:
            out.append(f"  ... {len(rep.hits) - top} more (use --top or --output-format json)")
    if rep.subnets:
        out.append("\nSubnets with several offending IPs (/24 IPv4, /48 IPv6)")
        for n in rep.subnets[:10]:
            out.append(f"  {n['subnet']:<24} ips={n['ips']:<4} total_score={n['total_score']}")
    out.append(f"\nWould block ({len(rep.blocks)}): dry-run only; blocking needs the firewall commands (M4).")
    for b in rep.blocks[:top]:
        out.append(f"  {b['ip']:<40} score={b['score']:<7} rules={','.join(b['rules'])}")
    if rep.protected:
        out.append(f"\nProtected, NOT blocked ({len(rep.protected)})")
        for p in rep.protected[:top]:
            out.append(f"  {p['ip']:<40} score={p['score']:<7} reason={p['reason']}")
    if rep.evicted:
        out.append(f"\nOver the block cap, dropped lowest-score first: {len(rep.evicted)}")
    if not (rep.hits or rep.host_findings):
        out.append("\nNo detections.")
    return "\n".join(out)
