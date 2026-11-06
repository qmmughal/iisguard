"""WordPress: version from wp-includes/version.php, leftover wp-content/upgrade folders."""

from __future__ import annotations

import os
import re
from pathlib import Path

from iisguard.audit.inventory import Item

_WP_RX = re.compile(r"""\$wp_version\s*=\s*['"]([^'"]+)['"]""")


def parse_version_php(text: str) -> str | None:
    m = _WP_RX.search(text)
    return m.group(1) if m else None


def find_installs(roots: list[str], max_depth: int = 4) -> list[Path]:
    out: list[Path] = []
    for r in roots:
        root = Path(r)
        if not root.is_dir():
            continue
        base = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            depth = len(Path(dirpath).parts) - base
            if "version.php" in filenames and Path(dirpath).name == "wp-includes":
                out.append(Path(dirpath).parent)
                dirnames[:] = []
                continue
            if depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git")]
    return out


def collect(roots: list[str]) -> list[Item]:
    items: list[Item] = []
    for site in find_installs(roots):
        try:
            text = (site / "wp-includes" / "version.php").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        v = parse_version_php(text)
        if not v:
            continue
        upg = site / "wp-content" / "upgrade"
        entries = sorted(p.name for p in upg.iterdir()) if upg.is_dir() else []
        extra: dict[str, object] = {"upgrade_dir_present": upg.is_dir(), "upgrade_dir_entries": entries[:20]}
        items.append(Item("wordpress", v, str(site), "version.php", extra))
    return items
