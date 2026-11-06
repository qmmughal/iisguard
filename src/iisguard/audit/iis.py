"""IIS presence/version (registry InetStp). IIS is patched through Windows cumulative updates."""

from __future__ import annotations

import sys

from iisguard.audit.inventory import Item


def collect() -> list[Item]:
    if sys.platform != "win32":
        return []
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\InetStp") as k:
            major = int(winreg.QueryValueEx(k, "MajorVersion")[0])
            minor = int(winreg.QueryValueEx(k, "MinorVersion")[0])
    except OSError:
        return []
    return [Item("iis", f"{major}.{minor}", "InetStp", "registry")]
