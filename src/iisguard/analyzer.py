"""Streaming analyzer: rule scoring, sliding windows, spray detection, subnet aggregation.

State is bounded: per-IP deques have a fixed maxlen and idle entries are pruned.
Input is assumed to be roughly chronological (as logs are). Events with ts == 0
are scored by rules but skipped by the time-window detectors.
"""

from __future__ import annotations

import ipaddress
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from iisguard.config import Config
from iisguard.firewall.safety import Protector
from iisguard.models import SEVERITY_RANK, Hit, LogEvent, Rule
from iisguard.rules import RuleSet

_STATIC = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".map", ".webp", ".mp4", ".webm", ".eot",
)  # fmt: skip


def _behavior(rid: str, score: int, severity: str, description: str) -> Rule:
    return Rule(rid, "behavior", score, severity, "behavior", "", description)


BEHAVIORS: dict[str, Rule] = {
    r.id: r
    for r in (
        _behavior("behav-flood", 80, "high", "Request flood from one IP"),
        _behavior("behav-scan-4xx", 60, "medium", "Burst of 4xx responses (content/path scanning)"),
        _behavior("behav-bruteforce", 100, "high", "Many login attempts from one IP"),
        _behavior("behav-spray", 70, "high", "Part of a distributed password-spray campaign"),
    )
}


class _LoginState:
    __slots__ = ("q", "counts", "low", "active", "flagged", "bruted", "campaign_ips", "first", "last")

    def __init__(self) -> None:
        self.q: deque[tuple[float, str]] = deque()
        self.counts: dict[str, int] = {}
        self.low = 0  # IPs whose attempt count is within 1..per_ip_max
        self.active = False
        self.flagged: set[str] = set()
        self.bruted: dict[str, float] = {}
        self.campaign_ips: set[str] = set()
        self.first = 0.0
        self.last = 0.0


@dataclass
class Report:
    stats: dict[str, Any] = field(default_factory=dict)
    hits: list[Hit] = field(default_factory=list)
    host_findings: list[dict[str, Any]] = field(default_factory=list)
    subnets: list[dict[str, Any]] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    blocks: list[dict[str, Any]] = field(default_factory=list)
    protected: list[dict[str, Any]] = field(default_factory=list)
    evicted: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stats": self.stats,
            "detections": [h.__dict__ for h in self.hits],
            "host_findings": self.host_findings,
            "subnets": self.subnets,
            "blocks": self.blocks,
            "protected_not_blocked": self.protected,
            "evicted_over_cap": self.evicted,
        }

    @property
    def max_severity(self) -> str:
        sev = [h.severity for h in self.hits] + [f["severity"] for f in self.host_findings]
        return max(sev, key=lambda s: SEVERITY_RANK[s], default="info")


class Analyzer:
    def __init__(self, ruleset: RuleSet, cfg: Config, protector: Protector | None = None) -> None:
        self.rules = ruleset
        self.cfg = cfg
        self.protector = protector or Protector()
        self.hits: dict[tuple[str, str], Hit] = {}
        self.scores: dict[str, float] = {}
        self._req: dict[str, deque[float]] = {}
        self._err: dict[str, deque[float]] = {}
        self._crash: deque[float] = deque(maxlen=cfg.crash_burst_count)
        self._crash_findings: list[dict[str, Any]] = []
        self._login: dict[str, _LoginState] = {}
        self._login_rx = re.compile("^(?:" + "|".join(cfg.login_paths) + ")/?$", re.IGNORECASE)
        self._events = 0
        self._last_prune = 0.0

    # ------------------------------------------------------------------ scoring
    def _add(self, ip: str, rule: Rule, ts: float, sample: str, boost: float = 1.0) -> None:
        key = (ip, rule.id)
        h = self.hits.get(key)
        if h is None:
            h = Hit(ip, rule.id, rule.category, rule.severity, rule.score, 0, ts, ts, [], list(rule.cve))
            self.hits[key] = h
            inc = rule.score * boost
        else:
            inc = rule.score * boost * 0.2 if h.count <= 5 else 0.0  # repeats count a little, capped
        h.count += 1
        h.last_ts = ts
        if len(h.samples) < 3:
            h.samples.append(sample[:200])
        if inc:
            self.scores[ip] = self.scores.get(ip, 0.0) + inc

    # ------------------------------------------------------------------ main entry
    def feed(self, ev: LogEvent) -> None:
        self._events += 1
        ts = ev.ts
        ip = ev.ip
        for rule in self.rules.match(ev):
            if rule.category == "php-crash":
                self._on_crash(ts, ev.message)
            elif ip:
                boost = 1.5 if 200 <= ev.status < 300 and SEVERITY_RANK[rule.severity] >= 3 else 1.0
                self._add(ip, rule, ts, ev.uri or ev.message, boost)
        if not ip or not ev.method or ts <= 0:
            return
        path = ev.path
        cfg = self.cfg
        if not path.endswith(_STATIC):
            dq = self._req.get(ip)
            if dq is None:
                dq = self._req[ip] = deque(maxlen=cfg.flood_requests)
            if dq and ts < dq[-1]:  # time went backwards (rotated/merged logs): restart the window
                dq.clear()
            dq.append(ts)
            if len(dq) == cfg.flood_requests and 0 <= ts - dq[0] <= cfg.flood_window:
                self._add(ip, BEHAVIORS["behav-flood"], ts, f"{cfg.flood_requests} requests in {ts - dq[0]:.0f}s")
                dq.clear()
        if 400 <= ev.status < 500:
            eq = self._err.get(ip)
            if eq is None:
                eq = self._err[ip] = deque(maxlen=cfg.scan4xx_count)
            if eq and ts < eq[-1]:
                eq.clear()
            eq.append(ts)
            if len(eq) == cfg.scan4xx_count and 0 <= ts - eq[0] <= cfg.scan4xx_window:
                self._add(ip, BEHAVIORS["behav-scan-4xx"], ts, f"{cfg.scan4xx_count} 4xx in {ts - eq[0]:.0f}s")
                eq.clear()
        if ev.method == "POST" and self._login_rx.match(path):
            self._on_login(path.lower().rstrip("/"), ip, ts)
        if ts - self._last_prune > 300:
            self._prune(ts)

    def _prune(self, now: float) -> None:
        self._last_prune = now
        for table, win in ((self._req, self.cfg.flood_window), (self._err, self.cfg.scan4xx_window)):
            for k in [k for k, d in table.items() if not d or now - d[-1] > win]:
                del table[k]

    def _on_crash(self, ts: float, msg: str) -> None:
        if ts <= 0:
            return
        self._crash.append(ts)
        c = self.cfg
        if len(self._crash) == c.crash_burst_count and 0 <= ts - self._crash[0] <= c.crash_burst_window:
            self._crash_findings.append(
                {
                    "id": "host-php-crash-burst",
                    "severity": "high",
                    "kind": "php-crash-burst",
                    "detail": f"{c.crash_burst_count} PHP fatal/crash lines in {ts - self._crash[0]:.0f}s",
                    "first_ts": self._crash[0],
                    "last_ts": ts,
                    "sample": msg[:200],
                }
            )
            self._crash.clear()

    def _on_login(self, path: str, ip: str, ts: float) -> None:
        cfg = self.cfg
        st = self._login.get(path)
        if st is None:
            st = self._login[path] = _LoginState()
            st.first = ts
        st.last = ts
        cut = ts - cfg.spray_window
        q, counts = st.q, st.counts
        while q and q[0][0] < cut:
            _, old = q.popleft()
            c = counts[old]
            if c == 1:
                del counts[old]
                st.low -= 1
                st.flagged.discard(old)
            else:
                counts[old] = c - 1
                if c - 1 == cfg.spray_per_ip_max:
                    st.low += 1
        q.append((ts, ip))
        c = counts.get(ip, 0) + 1
        counts[ip] = c
        if c == 1:
            st.low += 1
        elif c == cfg.spray_per_ip_max + 1:
            st.low -= 1
        if c >= cfg.brute_attempts and ts - st.bruted.get(ip, -1e18) >= cfg.spray_window:
            st.bruted[ip] = ts
            self._add(ip, BEHAVIORS["behav-bruteforce"], ts, f"{c} login POSTs to {path} in window")
        if st.low >= cfg.spray_min_ips:
            if not st.active:
                st.active = True
                for i, n in counts.items():
                    if n <= cfg.spray_per_ip_max and i not in st.flagged:
                        self._flag_spray(st, i, path, ts)
            elif c <= cfg.spray_per_ip_max and ip not in st.flagged:
                self._flag_spray(st, ip, path, ts)
        elif st.active and st.low < cfg.spray_min_ips:
            st.active = False

    def _flag_spray(self, st: _LoginState, ip: str, path: str, ts: float) -> None:
        st.flagged.add(ip)
        st.campaign_ips.add(ip)
        self._add(ip, BEHAVIORS["behav-spray"], ts, f"spray campaign on {path}")

    # ------------------------------------------------------------------ results
    @staticmethod
    def _subnet(ip: str) -> str | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
            a = a.ipv4_mapped
        bits = 24 if a.version == 4 else 48
        return str(ipaddress.ip_network(f"{a}/{bits}", strict=False))

    def finish(self) -> Report:
        cfg = self.cfg
        rep = Report()
        rep.hits = sorted(self.hits.values(), key=lambda h: (-SEVERITY_RANK[h.severity], -h.score, h.ip))
        rep.scores = {ip: round(s, 1) for ip, s in self.scores.items()}
        rep.host_findings.extend(self._crash_findings)
        for path, st in self._login.items():
            if st.campaign_ips:
                nets = {n for n in (self._subnet(i) for i in st.campaign_ips) if n}
                rep.host_findings.append(
                    {
                        "id": "host-password-spray",
                        "severity": "high",
                        "kind": "distributed-spray",
                        "detail": f"{len(st.campaign_ips)} IPs from {len(nets)} subnets sprayed {path}",
                        "first_ts": st.first,
                        "last_ts": st.last,
                        "ips": sorted(st.campaign_ips)[:50],
                    }
                )
        groups: dict[str, list[str]] = {}
        for ip, sc in self.scores.items():
            net = self._subnet(ip)
            if net and sc > 0:
                groups.setdefault(net, []).append(ip)
        for net, ips in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            if len(ips) >= cfg.subnet_min_ips:
                rep.subnets.append(
                    {
                        "subnet": net,
                        "ips": len(ips),
                        "total_score": round(sum(self.scores[i] for i in ips), 1),
                    }
                )
        # Block decision: threshold -> safety filter -> cap (lowest scores evicted first).
        candidates = sorted(((ip, sc) for ip, sc in self.scores.items() if sc >= cfg.block_score), key=lambda x: -x[1])
        allowed: list[tuple[str, float]] = []
        for ip, sc in candidates:
            why = self.protector.reason(ip)
            if why:
                rep.protected.append({"ip": ip, "score": round(sc, 1), "reason": why})
            else:
                allowed.append((ip, sc))
        for ip, sc in allowed[cfg.max_blocks :]:
            rep.evicted.append({"ip": ip, "score": round(sc, 1)})
        for ip, sc in allowed[: cfg.max_blocks]:
            rules = sorted({h.rule_id for h in rep.hits if h.ip == ip})
            rep.blocks.append({"ip": ip, "score": round(sc, 1), "rules": rules})
        rep.stats = {"events": self._events, "ips_scored": len(self.scores)}
        return rep
