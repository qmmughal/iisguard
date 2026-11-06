"""Installed .NET runtimes (`dotnet --list-runtimes`) and self-contained apps (*.deps.json)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from iisguard.audit.inventory import Item
from iisguard.audit.util import Runner, run_cmd

_RT_RX = re.compile(r"^(Microsoft\.[A-Za-z.]+)\s+(\d+\.\d+\.\d+\S*)\s+\[(.+)\]\s*$", re.MULTILINE)
_LIB_RX = re.compile(
    r"^(?:runtimepack\.)?Microsoft\.(NETCore|AspNetCore)\.App\.Runtime\.[A-Za-z0-9.\-]+/(\d+\.\d+\.\d+\S*)$"
)


def parse_list_runtimes(out: str) -> list[Item]:
    return [
        Item("dotnet-runtime", m.group(2), m.group(3), "cli", {"runtime_name": m.group(1)})
        for m in _RT_RX.finditer(out)
    ]


def scan_self_contained(roots: list[str], max_files: int = 5000) -> list[Item]:
    """A self-contained app bundles its own runtime, so OS/host patching does not fix it."""
    items: list[Item] = []
    seen = 0
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not fn.lower().endswith(".deps.json"):
                    continue
                seen += 1
                if seen > max_files:
                    return items
                p = Path(dirpath) / fn
                try:
                    data = json.loads(p.read_text(encoding="utf-8-sig"))
                except (OSError, ValueError):
                    continue
                libs = data.get("libraries") if isinstance(data, dict) else None
                if not isinstance(libs, dict):
                    continue
                for key in libs:
                    m = _LIB_RX.match(str(key))
                    if m:
                        name = "Microsoft.AspNetCore.App" if m.group(1) == "AspNetCore" else "Microsoft.NETCore.App"
                        extra: dict[str, object] = {"runtime_name": name, "self_contained": True}
                        items.append(Item("dotnet-runtime", m.group(2), str(p), "deps.json", extra))
    return items


def collect(app_roots: list[str] | None = None, runner: Runner = run_cmd) -> list[Item]:
    items = parse_list_runtimes(runner(["dotnet", "--list-runtimes"]))
    if app_roots:
        items += scan_self_contained(app_roots)
    return items
