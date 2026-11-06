"""File-integrity monitoring: hash a webroot into a baseline, then report what changed.

The baseline is a plain JSON file. Keep a copy somewhere an attacker on the web server cannot write:
an attacker who can edit the baseline can hide changes (documented limit).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iisguard import __version__
from iisguard.webshell import SCRIPT_EXTS, SKIP_DIRS, UPLOAD_DIR_RX

WATCH_EXTS = SCRIPT_EXTS | {
    ".config",
    ".ini",
    ".htaccess",
    ".js",
    ".html",
    ".htm",
    ".json",
    ".dll",
    ".exe",
    ".cmd",
    ".bat",
    ".ps1",
    ".sh",
}
WATCH_NAMES = {"web.config", ".htaccess", ".user.ini", "php.ini", "wp-config.php", "appsettings.json"}
VOLATILE_DIRS = ("wp-content/cache", "wp-content/upgrade", "/cache/", "/logs/", "/log/")
MAX_HASH_BYTES = 50 * 1024 * 1024


@dataclass
class FimResult:
    added: list[dict[str, Any]] = field(default_factory=list)
    modified: list[dict[str, Any]] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    baseline_created: float = 0.0

    @property
    def changed(self) -> bool:
        return bool(self.added or self.modified or self.deleted)

    def to_dict(self) -> dict[str, Any]:
        return {"added": self.added, "modified": self.modified, "deleted": self.deleted,
                "baseline_created": self.baseline_created}  # fmt: skip


def _wanted(path: Path, include_all: bool) -> bool:
    if include_all:
        return True
    return path.suffix.lower() in WATCH_EXTS or path.name.lower() in WATCH_NAMES


def _sha256(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def snapshot(root: Path, include_all: bool = False) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if not _wanted(p, include_all) or any(v in "/" + rel.lower() for v in VOLATILE_DIRS):
                continue
            try:
                st = p.lstat()
            except OSError:
                continue
            if p.is_symlink() or st.st_size > MAX_HASH_BYTES:
                continue
            digest = _sha256(p)
            if digest:
                files[rel] = {"sha256": digest, "size": st.st_size, "mtime": st.st_mtime}
    return files


def init_baseline(root: str, baseline: str, include_all: bool = False) -> int:
    r = Path(root).resolve()
    data = {
        "tool": f"iisguard {__version__}",
        "root": str(r),
        "created": time.time(),
        "include_all": include_all,
        "files": snapshot(r, include_all),
    }
    out = Path(baseline)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(out)
    return len(data["files"])  # type: ignore[arg-type]


def check_baseline(root: str, baseline: str) -> FimResult:
    base = json.loads(Path(baseline).read_text(encoding="utf-8"))
    if not isinstance(base, dict) or "files" not in base:
        raise ValueError("not an iisguard FIM baseline")
    r = Path(root).resolve()
    old: dict[str, dict[str, Any]] = base["files"]
    new = snapshot(r, bool(base.get("include_all")))
    res = FimResult(baseline_created=float(base.get("created", 0)))
    for rel, meta in sorted(new.items()):
        if rel not in old:
            is_script = Path(rel).suffix.lower() in SCRIPT_EXTS
            res.added.append(
                {"path": rel, "sha256": meta["sha256"], "suspicious": is_script and bool(UPLOAD_DIR_RX.search(rel))}
            )
        elif old[rel]["sha256"] != meta["sha256"]:
            res.modified.append({"path": rel, "old_sha256": old[rel]["sha256"], "sha256": meta["sha256"]})
    res.deleted = sorted(set(old) - set(new))
    return res
