"""Rotate hard-coded machineKeys. New keys are random (CSPRNG), same length as the old ones, and NEVER printed."""

from __future__ import annotations

import re
import secrets
from pathlib import Path

from iisguard.audit import webconfig
from iisguard.fix.base import Change, FixPlan, read_text
from iisguard.fix.xmledit import validate

TAG_RX = re.compile(r"<machineKey\b[^>]*>", re.I | re.S)
ATTR_RX = r'(\b{name}\s*=\s*")([^"]*)(")'


def _fresh(old: str, default_bytes: int) -> str:
    n = len(old) // 2 if re.fullmatch(r"[0-9A-Fa-f]{16,}", old) and len(old) % 2 == 0 else default_bytes
    return secrets.token_hex(n).upper()


def _rotate_tag(tag: str) -> str:
    for name, default in (("validationKey", 64), ("decryptionKey", 32)):

        def repl(m: re.Match[str], d: int = default) -> str:
            return m.group(1) + _fresh(m.group(2), d) + m.group(3)

        tag = re.sub(ATTR_RX.format(name=name), repl, tag, flags=re.I)
    return tag


def _is_explicit(tag: str) -> bool:
    m = re.search(ATTR_RX.format(name="validationKey"), tag, re.I)
    return bool(m and m.group(2) and not m.group(2).lower().startswith("autogenerate"))


def mask_keys(text: str, new: bool = False) -> str:
    label = "NEW random key hidden" if new else "old key hidden"
    return re.sub(r'((?:validation|decryption)Key\s*=\s*")[^"]*(")', rf"[{label}]", text, flags=re.I)


def plan(paths: list[str], all_hardcoded: bool = False) -> FixPlan:
    audit = webconfig.audit_roots(paths)
    shared = {f.path for f in audit.findings if f.id == "machinekey-shared"}
    hard = {f.path for f in audit.findings if f.id == "machinekey-hardcoded"}
    targets = sorted(hard if all_hardcoded else shared)
    fp = FixPlan("machinekey")
    for t in targets:
        p = Path(t)
        old = read_text(p)
        new = TAG_RX.sub(lambda m: _rotate_tag(m.group(0)) if _is_explicit(m.group(0)) else m.group(0), old)
        validate(new)
        if new != old:
            fp.changes.append(
                Change(p, new, "replace machineKey with unique random keys (values hidden)", old, mask_keys)
            )
    if not targets:
        fp.notes.append(
            "Nothing to rotate. Default scope is keys shared by more than one web.config; use --all-hardcoded to include every "
            "hard-coded key."
        )
    fp.notes += [
        "Rotating keys invalidates existing sessions, forms-auth cookies and ViewState; users will be signed out.",
        "Web FARM: every node must receive the SAME new key for a site. Apply on one node and copy the section to the others.",
        "Recycle the affected application pools afterwards (iisguard does not run appcmd for you).",
        "If the old key may have been exposed, treat earlier forged ViewState/auth tokens as possible: review logs and hunt for web-shells.",
    ]
    return fp
