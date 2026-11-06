"""JSON-lines access logs (nginx json_combined, Caddy, Traefik, Envoy, app logs...)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any

from iisguard.logs.base import decode_uri
from iisguard.models import LogEvent, ParseStats

_IP = ("remote_addr", "client_ip", "clientip", "ip", "c-ip", "remote_ip", "src_ip", "http_x_real_ip")
_URI = ("request_uri", "uri", "url", "path", "cs-uri")
_METHOD = ("request_method", "method", "verb", "cs-method")
_STATUS = ("status", "status_code", "sc-status", "response_code")
_UA = ("http_user_agent", "user_agent", "ua", "useragent", "agent")
_TIME = ("time_iso8601", "@timestamp", "timestamp", "time", "ts", "datetime")


def _first(d: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _ts(v: Any) -> float:
    if isinstance(v, (int, float)):
        return float(v) / 1000.0 if v > 1e11 else float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(v)
        except ValueError:
            return 0.0
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()
    return 0.0


def parse(lines: Iterable[str], stats: ParseStats) -> Iterator[LogEvent]:
    for line in lines:
        stats.lines += 1
        if line[:1] != "{":
            if line.strip():
                stats.bad += 1
            continue
        try:
            d = json.loads(line)
        except ValueError:
            stats.bad += 1
            continue
        if not isinstance(d, dict):
            stats.bad += 1
            continue
        ip = _first(d, _IP)
        if ip is None:
            stats.bad += 1
            continue
        uri = _first(d, _URI)
        method = _first(d, _METHOD)
        req = d.get("request")
        if isinstance(req, str) and (uri is None or method is None):
            parts = req.split(" ", 2)
            if len(parts) >= 2:
                method, uri = method or parts[0], uri or parts[1]
        status = _first(d, _STATUS)
        full, path, query = decode_uri(str(uri or ""))
        stats.events += 1
        yield LogEvent(
            ts=_ts(_first(d, _TIME)),
            ip=str(ip),
            method=str(method or ""),
            uri=full,
            path=path,
            query=query,
            status=int(status) if str(status).isdigit() else 0,
            ua=str(_first(d, _UA) or ""),
            raw=line,
        )
