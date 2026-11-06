"""Shared helpers for log parsers."""

from __future__ import annotations

import gzip
import sys
from collections.abc import Iterator
from typing import IO
from urllib.parse import unquote


def _dec(s: str) -> str:
    for _ in range(2):  # catch double-encoding
        n = unquote(s, encoding="latin-1")
        if n == s:
            break
        s = n
    return s


def decode_uri(raw: str) -> tuple[str, str, str]:
    """Return (uri, path, query), percent-decoded; '+' in the query becomes a space."""
    path, sep, query = raw.partition("?")
    if "%" in path:
        path = _dec(path)
    if "%" in query or "+" in query:
        query = _dec(query.replace("+", " "))
    return (path + "?" + query if sep else path), path, query


def open_lines(path: str) -> Iterator[str]:
    """Stream a log file (plain, .gz, or '-' for stdin) one line at a time.

    latin-1 never fails to decode and is the fastest codec; URIs are ASCII and the
    only non-ASCII we care about is inside user agents.
    """
    if path == "-":
        stream: IO[str] = sys.stdin
        yield from stream
        return
    if path.lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="latin-1", newline="\n") as gz:
            yield from gz
        return
    with open(path, encoding="latin-1", newline="\n", buffering=1 << 20) as f:
        yield from f
