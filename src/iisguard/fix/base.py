"""Shared machinery for fixes: every fix PLANS changes, shows a diff, and only writes with --apply.

Before any write the original file is copied to <state>/backups/<id>/ with a manifest, so `fix --rollback` can
restore it. Rollback refuses to touch a file that changed after the fix (unless forced). Files are read and written
byte-faithfully (BOM and line endings preserved).
"""

from __future__ import annotations

import difflib
import hashlib
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iisguard.state import new_id, read_json, write_json


class FixError(RuntimeError):
    pass


@dataclass
class Change:
    path: Path
    new: str
    description: str
    old: str | None = None  # None = file will be created
    mask: Callable[[str, bool], str] | None = None  # hides secrets in the diff; second arg is True for the new text


@dataclass
class FixPlan:
    name: str
    changes: list[Change] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # warnings and follow-up steps
    snippets: dict[str, str] = field(default_factory=dict)  # copy-paste config for other servers

    def diff(self) -> str:
        out: list[str] = []
        for c in self.changes:
            out.append(f"--- {c.path}  ({c.description})")
            m = c.mask or (lambda s, _new: s)
            old = (m(c.old, False) if c.old is not None else "").splitlines(keepends=True)
            new = m(c.new, True).splitlines(keepends=True)
            d = list(difflib.unified_diff(old, new, "before" if c.old is not None else "(new file)", "after", n=2))
            out.append("".join(d) if d else "(no change)")
        return "\n".join(out)


def read_text(path: Path) -> str:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return f.read()


def had_bom(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(3) == b"\xef\xbb\xbf"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def eol(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def backups_dir(state: Path) -> Path:
    return state / "backups"


def apply_plan(plan: FixPlan, state: Path) -> str:
    """Back up, then write. Returns the backup id."""
    bid = new_id() + "-" + re.sub(r"[^a-z0-9]+", "", plan.name.lower())[:12]
    bdir = backups_dir(state) / bid
    entries: list[dict[str, Any]] = []
    written: list[Change] = []
    try:
        for i, c in enumerate(plan.changes):
            existed = c.path.exists()
            ent: dict[str, Any] = {"path": str(c.path), "existed": existed, "backup": "", "sha_before": ""}
            if existed:
                if c.path.is_symlink():
                    raise FixError(f"refusing to modify symlink {c.path}")
                bdir.mkdir(parents=True, exist_ok=True)
                dest = bdir / f"{i}.bak"
                shutil.copy2(c.path, dest)
                ent["backup"], ent["sha_before"] = dest.name, sha(c.path)
            bom = existed and had_bom(c.path)
            c.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = c.path.with_name(c.path.name + ".iisguard-tmp")
            with open(tmp, "w", encoding="utf-8-sig" if bom else "utf-8", newline="") as f:
                f.write(c.new)
            tmp.replace(c.path)
            ent["sha_after"] = sha(c.path)
            entries.append(ent)
            written.append(c)
    except Exception:
        _restore(entries, force=True)  # undo whatever was written before the failure
        raise
    write_json(bdir / "manifest.json", {"fix": plan.name, "time": time.time(), "entries": entries})
    return bid


def _restore(entries: list[dict[str, Any]], force: bool, bdir: Path | None = None) -> list[str]:
    done: list[str] = []
    for ent in reversed(entries):
        p = Path(ent["path"])
        if p.exists() and not force and ent.get("sha_after") and sha(p) != ent["sha_after"]:
            raise FixError(f"{p} changed after the fix was applied; use --force to overwrite")
        if ent["existed"] and bdir is not None:
            shutil.copy2(bdir / ent["backup"], p)
        elif not ent["existed"] and p.exists():
            p.unlink()
        done.append(str(p))
    return done


def list_backups(state: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    root = backups_dir(state)
    if root.is_dir():
        for d in sorted(root.iterdir()):
            m = read_json(d / "manifest.json", None)
            if m:
                out.append(
                    {"id": d.name, "fix": m["fix"], "time": m["time"], "files": [e["path"] for e in m["entries"]]}
                )
    return out


def rollback(state: Path, backup_id: str | None = None, force: bool = False) -> tuple[str, list[str]]:
    backups = list_backups(state)
    if not backups:
        raise FixError("no fix backups found")
    bid = backup_id or backups[-1]["id"]
    bdir = backups_dir(state) / bid
    manifest = read_json(bdir / "manifest.json", None)
    if not manifest:
        raise FixError(f"unknown backup id {bid}")
    return bid, _restore(manifest["entries"], force, bdir)
