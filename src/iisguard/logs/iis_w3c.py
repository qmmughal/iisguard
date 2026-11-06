"""IIS W3C extended log format (honours the #Fields: directive, UTC timestamps)."""

from __future__ import annotations

import calendar
from collections.abc import Iterable, Iterator

from iisguard.logs.base import decode_uri
from iisguard.models import LogEvent, ParseStats

_REQUIRED = ("date", "time", "cs-method", "cs-uri-stem", "c-ip")


def parse(lines: Iterable[str], stats: ParseStats) -> Iterator[LogEvent]:
    cols: dict[str, int] | None = None
    need = 0
    day_cache: dict[str, int] = {}
    i_date = i_time = i_method = i_stem = i_query = i_ip = i_ua = i_status = -1
    for line in lines:
        stats.lines += 1
        if line[:1] == "#":
            if line.startswith("#Fields:"):
                cols = {n: i for i, n in enumerate(line[8:].split())}
                if not all(r in cols for r in _REQUIRED):
                    cols = None
                    continue
                i_date, i_time = cols["date"], cols["time"]
                i_method, i_stem, i_ip = cols["cs-method"], cols["cs-uri-stem"], cols["c-ip"]
                i_query = cols.get("cs-uri-query", -1)
                i_ua = cols.get("cs(User-Agent)", -1)
                i_status = cols.get("sc-status", -1)
                need = max(i_date, i_time, i_method, i_stem, i_ip, i_query, i_ua, i_status) + 1
            continue
        if len(line) < 12:
            continue
        if cols is None:
            stats.bad += 1
            continue
        p = line.rstrip("\r\n").split(" ")
        if len(p) < need:
            stats.bad += 1
            continue
        day = p[i_date]
        base = day_cache.get(day)
        if base is None:
            try:
                y, m, d = day.split("-")
                base = calendar.timegm((int(y), int(m), int(d), 0, 0, 0))
            except ValueError:
                stats.bad += 1
                continue
            day_cache[day] = base
        try:
            h, mi, s = p[i_time].split(":")
            ts = float(base + int(h) * 3600 + int(mi) * 60 + int(s))
        except ValueError:
            stats.bad += 1
            continue
        q = p[i_query] if i_query >= 0 else "-"
        uri, path, query = decode_uri(p[i_stem] + ("?" + q if q != "-" else ""))
        ua = p[i_ua] if i_ua >= 0 else ""
        status = p[i_status] if i_status >= 0 else ""
        stats.events += 1
        yield LogEvent(
            ts=ts,
            ip=p[i_ip],
            method=p[i_method],
            uri=uri,
            path=path,
            query=query,
            status=int(status) if status.isdigit() else 0,
            ua="" if ua == "-" else ua.replace("+", " "),
            raw=line,
        )
