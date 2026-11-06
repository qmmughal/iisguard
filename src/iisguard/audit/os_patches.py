"""Windows OS build + UBR. NVD publishes fixed build numbers, so no hand-maintained KB map is needed."""

from __future__ import annotations

import sys

from iisguard.audit.inventory import Item


def collect() -> list[Item]:
    if sys.platform != "win32":
        return []
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            build = str(winreg.QueryValueEx(k, "CurrentBuildNumber")[0])
            ubr = int(winreg.QueryValueEx(k, "UBR")[0])
            name = str(winreg.QueryValueEx(k, "ProductName")[0])
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\ProductOptions") as k:
            ptype = str(winreg.QueryValueEx(k, "ProductType")[0])
    except OSError:
        return []
    family = "client" if ptype.upper() == "WINNT" else "server"
    return [Item("windows", f"10.0.{build}.{ubr}", name, "registry", {"family": family, "product_name": name})]
