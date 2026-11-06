"""A tiny YAML-subset reader so the core stays standard-library only.

Supported: block mappings, block sequences (of scalars or mappings), single- and
double-quoted strings, ints, bools, null, ``[]`` and ``{}``, and full-line or
trailing ``# comments``. That is all rules.yaml and config files need. If PyYAML
is installed the loader in :mod:`iisguard.config` prefers it for config files.
"""

from __future__ import annotations

import json
import re
from typing import Any


class YamlError(ValueError):
    pass


_KEY = re.compile(r"^([A-Za-z0-9_.\-]+):(?:\s+(.*))?$")


def _scalar(text: str, lineno: int) -> Any:
    t = text.strip()
    if not t:
        return None
    if t[0] == "'":
        out: list[str] = []
        i = 1
        while i < len(t):
            if t[i] == "'":
                if i + 1 < len(t) and t[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                rest = t[i + 1 :].strip()
                if rest and not rest.startswith("#"):
                    raise YamlError(f"line {lineno}: junk after quoted string")
                return "".join(out)
            out.append(t[i])
            i += 1
        raise YamlError(f"line {lineno}: unterminated single-quoted string")
    if t[0] == '"':
        m = re.match(r'"((?:[^"\]|\.)*)"\s*(#.*)?$', t)
        if not m:
            raise YamlError(f"line {lineno}: bad double-quoted string")
        return json.loads('"' + m.group(1) + '"')
    t = re.split(r"\s#", t, maxsplit=1)[0].strip()
    low = t.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~"):
        return None
    if t == "[]":
        return []
    if t == "{}":
        return {}
    if t[0] == "[" and t[-1] == "]" and "'" not in t and '"' not in t:
        return [_scalar(p, lineno) for p in t[1:-1].split(",") if p.strip()]
    if t[0] in "[{":
        raise YamlError(f"line {lineno}: only simple unquoted inline lists and [] / {{}} are supported")
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    return t


def loads(text: str) -> Any:
    lines: list[tuple[int, str, int]] = []
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlError(f"line {n}: tabs are not allowed for indentation")
        lines.append((len(raw) - len(raw.lstrip(" ")), s, n))
    if not lines:
        return None
    pos = 0

    def block(indent: int) -> Any:
        nonlocal pos
        if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
            return seq(indent)
        return mapping(indent)

    def child(parent_indent: int, allow_same_seq: bool) -> Any:
        nonlocal pos
        if pos < len(lines):
            ind, content, _ = lines[pos]
            if ind > parent_indent:
                return block(ind)
            if allow_same_seq and ind == parent_indent and (content.startswith("- ") or content == "-"):
                return seq(ind)
        return None

    def mapping(indent: int) -> dict[str, Any]:
        nonlocal pos
        out: dict[str, Any] = {}
        while pos < len(lines):
            ind, content, n = lines[pos]
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(f"line {n}: unexpected indentation")
            if content.startswith("- "):
                break
            m = _KEY.match(content)
            if not m:
                raise YamlError(f"line {n}: expected 'key: value', got {content!r}")
            key, rest = m.group(1), m.group(2)
            if key in out:
                raise YamlError(f"line {n}: duplicate key {key!r}")
            pos += 1
            if rest is None or rest.strip() == "" or rest.strip().startswith("#"):
                out[key] = child(indent, True)
            else:
                out[key] = _scalar(rest, n)
        return out

    def seq(indent: int) -> list[Any]:
        nonlocal pos
        out: list[Any] = []
        while pos < len(lines):
            ind, content, n = lines[pos]
            if ind != indent or not (content.startswith("- ") or content == "-"):
                if ind > indent:
                    raise YamlError(f"line {n}: unexpected indentation")
                break
            rest = content[1:].strip()
            if not rest:
                pos += 1
                out.append(child(indent, False))
            elif _KEY.match(rest) and rest[0] not in "'\"":
                lines[pos] = (indent + 2, rest, n)  # treat as first key of a nested mapping
                out.append(mapping(indent + 2))
            else:
                pos += 1
                out.append(_scalar(rest, n))
        return out

    result = block(lines[0][0])
    if pos != len(lines):
        raise YamlError(f"line {lines[pos][2]}: could not parse")
    return result
