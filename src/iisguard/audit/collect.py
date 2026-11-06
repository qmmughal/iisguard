"""Gather a local inventory by running every collector (all read-only)."""

from __future__ import annotations

from iisguard.audit import dotnet, iis, os_patches, php, sharepoint_exchange, wordpress
from iisguard.audit.inventory import Item
from iisguard.audit.util import Runner, run_cmd


def collect_all(
    webroots: list[str] | None = None,
    app_roots: list[str] | None = None,
    php_dirs: list[str] | None = None,
    runner: Runner = run_cmd,
) -> list[Item]:
    items: list[Item] = []
    items += php.collect(php_dirs, runner)
    items += dotnet.collect(app_roots, runner)
    items += wordpress.collect(webroots or [])
    items += os_patches.collect()
    items += iis.collect()
    items += sharepoint_exchange.collect()
    return items
