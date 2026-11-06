"""Shared helpers for collectors. Collectors only READ: they run `<tool> -v`-style queries."""

from __future__ import annotations

import subprocess
from collections.abc import Callable

Runner = Callable[[list[str]], str]


def run_cmd(cmd: list[str], timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return (r.stdout or "") + (r.stderr or "")
