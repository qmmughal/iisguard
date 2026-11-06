"""Quarantine a suspicious file: move it out of the web tree, keep metadata, allow restore. Never executes it."""

from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path
from typing import Any

from iisguard.fix.base import FixError
from iisguard.state import new_id, read_json, write_json


def qdir(state: Path) -> Path:
    return state / "quarantine"


def plan(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file() or p.is_symlink():
        raise FixError(f"{path}: not a regular file (directories and symlinks are refused)")
    st = p.stat()
    return {"path": str(p.resolve()), "size": st.st_size, "mtime": st.st_mtime,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}  # fmt: skip


def apply(path: str, state: Path, reason: str = "") -> str:
    info = plan(path)
    qid = new_id()
    dest_dir = qdir(state) / qid
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / (Path(path).name + ".quarantined")
    shutil.move(str(path), dest)
    write_json(dest_dir / "meta.json", {**info, "id": qid, "stored": dest.name, "time": time.time(), "reason": reason})
    return qid


def list_items(state: Path) -> list[dict[str, Any]]:
    root = qdir(state)
    return [m for d in sorted(root.iterdir()) if (m := read_json(d / "meta.json", None))] if root.is_dir() else []


def restore(qid: str, state: Path, force: bool = False) -> str:
    d = qdir(state) / qid
    meta = read_json(d / "meta.json", None)
    if not meta:
        raise FixError(f"unknown quarantine id {qid}")
    target = Path(meta["path"])
    if target.exists() and not force:
        raise FixError(f"{target} exists; use --force to overwrite")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(d / meta["stored"]), target)
    shutil.rmtree(d, ignore_errors=True)
    return str(target)
