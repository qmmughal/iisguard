from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def build() -> object:
    spec = importlib.util.spec_from_file_location("build_bundle", ROOT / "scripts" / "build_bundle.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_zipapp_runs_and_finds_bundled_data(build: object, tmp_path: Path) -> None:
    pyz = build.build_pyz(tmp_path / "iisguard.pyz")  # type: ignore[attr-defined]
    env_dir = tmp_path / "state"
    run = lambda *a: subprocess.run(  # noqa: E731
        [sys.executable, "-I", str(pyz), *a],
        capture_output=True,
        text=True,
        timeout=60,
        env={"IISGUARD_STATE_DIR": str(env_dir), "SYSTEMROOT": "C:\\Windows"},
    )
    r = run("--version")
    assert r.returncode == 0 and "iisguard" in r.stdout
    r = run(
        "audit",
        "--kev",
        "--offline",
        "--inventory",
        str(ROOT / "tests" / "fixtures" / "inventory.json"),
        "--output-format",
        "json",
    )
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["kev"]["source"] == "snapshot" and any(f["cve"] == "CVE-2026-109618" for f in data["findings"])
    r = run("export", "sigma")
    assert r.returncode == 0 and "logsource" in r.stdout  # rules.yaml is readable from inside the archive


def test_bundle_zip_contents(build: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build, "dist", tmp_path)  # type: ignore[attr-defined]
    assert build.main() == 0  # type: ignore[attr-defined]
    with zipfile.ZipFile(tmp_path / "iisguard-windows-bundle.zip") as z:
        assert set(z.namelist()) == {"iisguard.pyz", "iisguard.cmd", "README.txt", "LICENSE", "iisguard.example.json"}
        json.loads(z.read("iisguard.example.json"))
        assert b"iisguard.pyz" in z.read("iisguard.cmd")
