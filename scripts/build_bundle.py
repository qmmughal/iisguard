"""Build dist/iisguard-windows-bundle.zip: a single-file iisguard.pyz plus launcher, README, LICENSE, example config.

    python scripts/build_bundle.py

Needs only Python 3.11+ on the target (the core is standard-library only). The .pyz is a zipapp: run it with
`py -3 iisguard.pyz --help` or use the included iisguard.cmd.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import zipapp
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
dist = root / "dist"
BUNDLE_README = """iisguard - Windows bundle
=========================
Requires Python 3.11 or newer (https://www.python.org/downloads/). Nothing else to install.

  iisguard.cmd --help
  iisguard.cmd scan C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex261107.log
  iisguard.cmd audit --kev
  iisguard.cmd hunt C:\\inetpub\\wwwroot

Everything is read-only / dry-run by default. See https://github.com/qmmughal/iisguard for the full documentation.
Verify this download against the SHA-256 shown on the GitHub release page before running it.
"""
LAUNCHER = '@echo off\r\nwhere py >nul 2>nul && (py -3 "%~dp0iisguard.pyz" %* & exit /b %errorlevel%)\r\npython "%~dp0iisguard.pyz" %*\r\n'


def build_pyz(target: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / "iisguard"
        shutil.copytree(root / "src" / "iisguard", pkg, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        target.parent.mkdir(parents=True, exist_ok=True)
        zipapp.create_archive(tmp, target, interpreter=None, main="iisguard.cli:main", compressed=True)
    return target


def main() -> int:
    pyz = build_pyz(dist / "iisguard.pyz")
    bundle = dist / "iisguard-windows-bundle.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(pyz, "iisguard.pyz")
        z.writestr("iisguard.cmd", LAUNCHER)
        z.writestr("README.txt", BUNDLE_README)
        z.write(root / "LICENSE", "LICENSE")
        z.write(root / "iisguard.example.json", "iisguard.example.json")
    print(f"built {pyz} and {bundle} ({bundle.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
