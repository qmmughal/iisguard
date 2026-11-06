"""nginx / Apache 'combined' (and 'common') access log format."""

from __future__ import annotations

import calendar
import re
from collections.abc import Iterable, Iterator

from iisguard.logs.base import decode_uri
from iisguard.models import LogEvent, ParseStats

LINE_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?')
_MONTHS = {m: i for i, m in enumerate(calendar.month_abbr) if m}


def parse_time(s: str, cache: dict[str, int]) -> float | None:
    """'07/Nov/2026:10:00:00 +0200' -> epoch seconds (UTC)."""
    day = s[:11]
    base = cache.get(day)
    if base is None:
        try:
            base = calendar.timegm((int(day[7:11]), _MONTHS[day[3:6]], int(day[:2]), 0, 0, 0))
        except (ValueError, KeyError):
            return None
        cache[day] = base
    try:
        secs = int(s[12:14]) * 3600 + int(s[15:17]) * 60 + int(s[18:20])
    except ValueError:
        return None
    tz = s[21:26]
    off = 0
    if len(tz) == 5 and tz[1:].isdigit():
        off = (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60) * (-1 if tz[0] == "-" else 1)
    return float(base + secs - off)


def parse(lines: Iterable[str], stats: ParseStats) -> Iterator[LogEvent]:
    match = LINE_RE.match
    cache: dict[str, int] = {}
    for line in lines:
        stats.lines += 1
        if len(line) < 20:
            continue
        m = match(line)
        if m is None:
            stats.bad += 1
            continue
        ip, tstr, req, status, _size, _ref, ua = m.groups()
        ts = parse_time(tstr, cache)
        if ts is None:
            stats.bad += 1
            continue
        parts = req.split(" ", 2)
        if len(parts) >= 2:
            method, target = parts[0], parts[1]
        else:
            method, target = "", req
        uri, path, query = decode_uri(target)
        stats.events += 1
        yield LogEvent(
            ts=ts,
            ip=ip,
            method=method,
            uri=uri,
            path=path,
            query=query,
            status=int(status),
            ua="" if ua is None or ua == "-" else ua,
            raw=line,
        )
