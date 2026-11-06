"""Where iisguard keeps its own data (block state, backups, quarantine, updated rule packs)."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any


def state_dir(override: str | None = None) -> Path:
    if override:
        return Path(override)
    env = os.environ.get("IISGUARD_STATE_DIR")
    if env:
        return Path(env)
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA") or os.environ.get("LOCALAPPDATA") or Path.home()) / "iisguard"
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "iisguard"


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, data: Any) -> None:
    """Atomic write: temp file then replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(path)


def new_id() -> str:
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + f"-{os.getpid() % 10000:04d}"
