"""Minimal text-level web.config editing that keeps comments and formatting. Result is validated as XML."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET


def validate(text: str) -> None:
    if "<!DOCTYPE" in text.upper():
        raise ValueError("DOCTYPE not allowed")
    ET.fromstring(text.lstrip("﻿"))


def has(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE) is not None


def new_config(inner: str, nl: str = "\n") -> str:
    return f'<?xml version="1.0" encoding="utf-8"?>{nl}<configuration>{nl}{inner}</configuration>{nl}'


def _wrap(path: list[str], fragment: str, nl: str, indent: int) -> str:
    pad = "  " * indent
    if not path:
        return "".join(f"{pad}{line}{nl}" for line in fragment.strip().splitlines())
    return f"{pad}<{path[0]}>{nl}{_wrap(path[1:], fragment, nl, indent + 1)}{pad}</{path[0]}>{nl}"


def insert(text: str, path: list[str], fragment: str) -> str:
    """Insert *fragment* (xml text) under the nested element *path*, creating missing levels."""
    nl = "\r\n" if "\r\n" in text else "\n"
    if not re.search(r"<configuration\b", text, re.I):
        return new_config(_wrap(path, fragment, nl, 1), nl)
    pos_open = 0  # search start inside the deepest element found so far
    pos_close = len(text)
    depth = 0
    for i, tag in enumerate(["configuration", *path]):
        m = re.compile(rf"<{re.escape(tag)}(\s[^>]*)?(/?)>", re.I).search(text, pos_open, pos_close)
        if not m:
            break
        if m.group(0).endswith("/>"):  # self-closing: expand it
            expanded = f"<{tag}{(m.group(1) or '').rstrip('/ ')}></{tag}>"
            text = text[: m.start()] + expanded + text[m.end() :]
            m = re.compile(rf"<{re.escape(tag)}(\s[^>]*)?>", re.I).search(text, m.start())
            assert m is not None
            pos_close = len(text)
        close = re.compile(rf"</{re.escape(tag)}\s*>", re.I).search(text, m.end(), pos_close)
        if not close:
            raise ValueError(f"unbalanced <{tag}> in web.config")
        pos_open, pos_close = m.end(), close.start()
        depth = i + 1
    missing = path[depth - 1 :] if depth else path
    block = _wrap(missing, fragment, nl, depth)
    # insert just before the closing tag of the deepest existing element, on its own line
    head = text[:pos_close].rstrip(" \t")
    if not head.endswith(("\n",)):
        head += nl
    return head + block + "  " * (depth - 1) + text[pos_close:]
