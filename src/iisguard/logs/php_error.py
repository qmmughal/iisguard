"""PHP / php-fpm / Apache-error-log lines that carry PHP errors and crashes."""

from __future__ import annotations

import calendar
import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime

from iisguard.models import LogEvent, ParseStats

# [07-Nov-2026 10:00:00 UTC] PHP Fatal error:  ...      (php error_log / php-fpm)
_PHP_RE = re.compile(r"^\[(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2})(?: [^\]]*)?\] (.*)$")
# [Sat Nov 07 10:00:00.123456 2026] [php:error] [pid 1] [client 1.2.3.4:5] PHP Fatal error: ...
_APACHE_RE = re.compile(
    r"^\[(\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\] \[[^\]]*\](?: \[pid [^\]]*\])?"
    r"(?: \[client ([^\]]+)\])? (.*)$"
)
_LEVEL_RE = re.compile(r"PHP (Fatal error|Parse error|Warning|Notice|Deprecated)", re.I)
_CRASH_RE = re.compile(r"exited on signal (?:6|11)|SIGSEGV|segfault|core dumped|Premature end of script", re.I)
_MONTHS = {m: i for i, m in enumerate(calendar.month_abbr) if m}


def _client_ip(client: str | None) -> str:
    if not client:
        return ""
    c = client.strip()
    if c.startswith("["):
        return c[1:].partition("]")[0]
    return c.rpartition(":")[0] if c.count(":") == 1 else c


def _level(msg: str) -> str:
    if _CRASH_RE.search(msg):
        return "crash"
    m = _LEVEL_RE.search(msg)
    if not m:
        return ""
    return {"fatal error": "fatal", "parse error": "parse"}.get(m.group(1).lower(), m.group(1).lower())


def parse(lines: Iterable[str], stats: ParseStats) -> Iterator[LogEvent]:
    for line in lines:
        stats.lines += 1
        if line[:1] != "[":
            continue  # stack-trace continuation lines etc.
        line = line.rstrip("\r\n")
        ts = 0.0
        ip = ""
        msg = ""
        m = _PHP_RE.match(line)
        if m:
            try:
                ts = datetime.strptime(m.group(1), "%d-%b-%Y %H:%M:%S").replace(tzinfo=UTC).timestamp()
            except ValueError:
                stats.bad += 1
                continue
            msg = m.group(2)
        else:
            a = _APACHE_RE.match(line)
            if not a:
                stats.bad += 1
                continue
            mon = _MONTHS.get(a.group(1)[4:7])
            if mon is None:
                stats.bad += 1
                continue
            day, hms = a.group(1)[8:].split()
            h, mi, s = hms.split(":")
            ts = float(calendar.timegm((int(a.group(2)), mon, int(day), int(h), int(mi), int(s))))
            ip = _client_ip(a.group(3))
            msg = a.group(4)
        stats.events += 1
        yield LogEvent(ts=ts, ip=ip, message=msg, level=_level(msg), raw=line)
