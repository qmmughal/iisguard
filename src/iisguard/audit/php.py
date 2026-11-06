"""Find PHP binaries (php, php-cgi, php-fpm), report version and session.upload_progress."""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

from iisguard.audit.inventory import Item
from iisguard.audit.util import Runner, run_cmd

_NAMES = ("php", "php-cgi", "php-fpm", "php.exe", "php-cgi.exe")
_FPM_GLOB = ("php-fpm", "php-fpm[0-9]*", "php[0-9]*-fpm")
_VER_RX = re.compile(r"^PHP (\d+\.\d+\.\d+\S*) \(([^)]*)\)", re.MULTILINE)
_INI_RX = re.compile(r"^session\.upload_progress\.enabled => (\S+)(?: => (\S+))?", re.MULTILINE)
_COMMON_DIRS_WIN = (r"C:\php", r"C:\Program Files\PHP", r"C:\Program Files (x86)\PHP", r"C:\tools\php")
_COMMON_DIRS_NIX = ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt/php/bin")
_SCAN_NAMES = ("php.exe", "php-cgi.exe", "php", "php-cgi", "php-fpm")


def find_binaries(extra_dirs: list[str] | None = None, max_depth: int = 3) -> list[str]:
    found: dict[str, str] = {}

    def add(p: str | Path) -> None:
        try:
            rp = os.path.realpath(p)
        except OSError:
            return
        if os.path.isfile(rp):
            found.setdefault(os.path.normcase(rp), rp)

    for n in _NAMES:
        w = shutil.which(n)
        if w:
            add(w)
    dirs = _COMMON_DIRS_WIN if sys.platform == "win32" else _COMMON_DIRS_NIX
    for d in dirs:
        base = Path(d)
        if not base.is_dir():
            continue
        for n in _NAMES:
            add(base / n)
        for pat in _FPM_GLOB:
            for p in base.glob(pat):
                add(p)
    for d in extra_dirs or []:
        root = Path(d)
        if not root.is_dir():
            continue
        root_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            if len(Path(dirpath).parts) - root_depth >= max_depth:
                dirnames[:] = []
            for fn in filenames:
                if fn.lower() in _SCAN_NAMES:
                    add(Path(dirpath) / fn)
    return sorted(found.values())


def parse_version_output(out: str) -> tuple[str, str] | None:
    m = _VER_RX.search(out)
    return (m.group(1), m.group(2)) if m else None


def parse_upload_progress(ini_out: str) -> str | None:
    """Effective (local) value of session.upload_progress.enabled from `php -i`, or None."""
    m = _INI_RX.search(ini_out)
    return m.group(1) if m else None


def collect(
    extra_dirs: list[str] | None = None, runner: Runner = run_cmd, binaries: list[str] | None = None
) -> list[Item]:
    items: list[Item] = []
    for b in binaries if binaries is not None else find_binaries(extra_dirs):
        parsed = parse_version_output(runner([b, "-v"]))
        if not parsed:
            continue
        version, sapi = parsed
        extra: dict[str, object] = {"sapi": sapi}
        up = parse_upload_progress(runner([b, "-i"]))
        if up is not None:
            extra["upload_progress"] = up
        items.append(Item("php", version, b, "cli", extra))
    return items
