"""On-prem SharePoint and Exchange: presence and build number from the registry."""

from __future__ import annotations

import sys

from iisguard.audit.inventory import Item


def collect() -> list[Item]:
    if sys.platform != "win32":
        return []
    import winreg

    items: list[Item] = []
    sp_key = r"SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\16.0"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sp_key) as k:
            build = str(winreg.QueryValueEx(k, "BuildVersion")[0])
        items.append(Item("sharepoint", build, sp_key, "registry"))
    except OSError:
        pass
    ex_key = r"SOFTWARE\Microsoft\ExchangeServer\v15\Setup"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ex_key) as k:
            names = ("MsiProductMajor", "MsiProductMinor", "MsiBuildMajor", "MsiBuildMinor")
            parts = [str(winreg.QueryValueEx(k, n)[0]) for n in names]
        items.append(Item("exchange", ".".join(parts), ex_key, "registry"))
    except OSError:
        pass
    return items
