"""Temporary php.ini hardening: session.upload_progress.enabled=0 (php.net 2026-10-21 / 2026-10-23 advisories).

This is a MITIGATION, not a patch: update PHP. It must go in php.ini / an FPM pool / server config, because php.net
says ini_set() and .user.ini do not work for this setting.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from iisguard.audit.util import Runner, run_cmd
from iisguard.fix.base import Change, FixPlan, eol, read_text

SOURCES = "https://www.php.net/archive/2026.php (2026-10-21 and 2026-10-23 notices)"


def find_php_ini(runner: Runner = run_cmd) -> str | None:
    out = runner(["php", "--ini"])
    for line in out.splitlines():
        if line.lower().startswith("loaded configuration file:"):
            val = line.split(":", 1)[1].strip()
            return None if val.startswith("(none)") else val
    return None


def set_ini(text: str, key: str, value: str, note: str) -> str:
    nl = eol(text)
    active = re.compile(rf"^(\s*{re.escape(key)}\s*=\s*)(.*?)(\s*(?:;.*)?)$", re.M)
    commented = re.compile(rf"^\s*;\s*{re.escape(key)}\s*=.*$", re.M)
    if m := active.search(text):
        if m.group(2).strip().strip('"').lower() == value.lower():
            return text
        repl = f"; {note} (was: {m.group(2).strip()}){nl}{key} = {value}"
        return text[: m.start()] + repl + text[m.end() :]
    if m := commented.search(text):
        return text[: m.end()] + f"{nl}; {note}{nl}{key} = {value}" + text[m.end() :]
    sep = "" if text.endswith(nl) or not text else nl
    return text + f"{sep}{nl}; {note}{nl}{key} = {value}{nl}"


def plan(ini_path: str | None, post_max_size: str | None = None, runner: Runner = run_cmd) -> FixPlan:
    fp = FixPlan("php-ini")
    path = ini_path or find_php_ini(runner)
    if not path:
        fp.notes.append(
            "No php.ini found. Pass --ini PATH, or set session.upload_progress.enabled=0 in your FPM pool/server config."
        )
        return fp
    p = Path(path)
    old = read_text(p)
    stamp = time.strftime("%Y-%m-%d", time.gmtime())
    new = set_ini(
        old,
        "session.upload_progress.enabled",
        "0",
        f"iisguard {stamp}: temporary mitigation, remove after patching ({SOURCES})",
    )
    if post_max_size:
        new = set_ini(new, "post_max_size", post_max_size, f"iisguard {stamp}: php.net hardening suggestion")
    if new != old:
        fp.changes.append(
            Change(
                p,
                new,
                "session.upload_progress.enabled = 0" + (f", post_max_size = {post_max_size}" if post_max_size else ""),
                old,
            )
        )
    else:
        fp.notes.append("php.ini already has the setting.")
    fp.notes += [
        "Restart every PHP worker (php-fpm, IIS FastCGI app pool, Apache) for the change to take effect.",
        "Check FPM pool files and the web server for php_admin_value / fastcgi_param overrides that set it back on.",
        "This reduces exposure to the confirmed session paths only. The real fix is updating PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later).",
        "Verify: php -i | findstr session.upload_progress.enabled (should show Off / 0).",
    ]
    return fp
