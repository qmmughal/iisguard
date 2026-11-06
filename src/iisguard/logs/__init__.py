"""Log readers. ``iter_events`` streams a file and yields normalized events."""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterable, Iterator

from iisguard.logs import combined, iis_w3c, json_lines, php_error
from iisguard.logs.base import open_lines
from iisguard.models import LogEvent, ParseStats

Parser = Callable[[Iterable[str], ParseStats], Iterator[LogEvent]]

PARSERS: dict[str, Parser] = {
    "iis": iis_w3c.parse,
    "combined": combined.parse,
    "php-error": php_error.parse,
    "json": json_lines.parse,
}
FORMAT_ALIASES = {
    "nginx": "combined",
    "apache": "combined",
    "w3c": "iis",
    "jsonl": "json",
    "php": "php-error",
}
FORMATS = ("auto", *PARSERS, *FORMAT_ALIASES)


class UnknownFormat(ValueError):
    pass


def detect_format(sample: Iterable[str]) -> str | None:
    """Guess the log format from the first lines of a file."""
    for line in sample:
        s = line.strip()
        if not s:
            continue
        if s.startswith(("#Software", "#Version", "#Date", "#Fields")):
            return "iis"
        if s.startswith("{"):
            return "json"
        if combined.LINE_RE.match(s):
            return "combined"
        if php_error._PHP_RE.match(s) or php_error._APACHE_RE.match(s):
            return "php-error"
    return None


def iter_events(path: str, fmt: str = "auto", stats: ParseStats | None = None) -> Iterator[LogEvent]:
    stats = stats if stats is not None else ParseStats()
    lines = open_lines(path)
    fmt = FORMAT_ALIASES.get(fmt, fmt)
    if fmt == "auto":
        head = list(itertools.islice(lines, 50))
        guessed = detect_format(head)
        if guessed is None:
            if not any(h.strip() for h in head):
                return
            raise UnknownFormat(f"{path}: could not detect log format; pass --format")
        fmt = guessed
        lines = itertools.chain(head, lines)
    if fmt not in PARSERS:
        raise UnknownFormat(f"unknown log format {fmt!r}; choose from {', '.join(FORMATS)}")
    stats.formats[fmt] = stats.formats.get(fmt, 0) + 1
    yield from PARSERS[fmt](lines, stats)
