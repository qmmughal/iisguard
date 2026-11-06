"""web.config audit: hard-coded / shared machineKeys, ViewState MAC, debug, tracing, request limits.

machineKey values are NEVER printed; only a short fingerprint (sha256 prefix) so shared keys can be matched.
"""

from __future__ import annotations

import hashlib
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from iisguard.models import SEVERITY_RANK

SKIP = {"bin", "obj", "node_modules", ".git"}
MAX_FILES = 3000


@dataclass
class ConfigFinding:
    path: str
    id: str
    severity: str
    detail: str
    fix: str = ""
    key_fingerprint: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "id": self.id, "severity": self.severity, "detail": self.detail,
                "fix": self.fix, "key_fingerprint": self.key_fingerprint}  # fmt: skip


@dataclass
class ConfigAudit:
    findings: list[ConfigFinding] = field(default_factory=list)
    files: int = 0
    skipped: list[str] = field(default_factory=list)


def _attr(el: ET.Element, name: str) -> str | None:
    for k, v in el.attrib.items():
        if k.lower() == name.lower():
            return v
    return None


def _walk(root: ET.Element, name: str) -> list[ET.Element]:
    return [e for e in root.iter() if e.tag.lower() == name.lower()]


def fingerprint(validation_key: str, decryption_key: str) -> str:
    return hashlib.sha256(f"{validation_key.strip().lower()}|{decryption_key.strip().lower()}".encode()).hexdigest()[
        :12
    ]


def audit_text(path: str, text: str) -> tuple[list[ConfigFinding], list[tuple[str, str]]]:
    """Return (findings, machine_key_fingerprints[(fingerprint, path)])."""
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("DOCTYPE/ENTITY in web.config is not parsed")
    root = ET.fromstring(text.lstrip("﻿"))
    out: list[ConfigFinding] = []
    keys: list[tuple[str, str]] = []

    def add(id_: str, sev: str, detail: str, fix: str = "", fp: str = "") -> None:
        out.append(ConfigFinding(path, id_, sev, detail, fix, fp))

    for mk in _walk(root, "machineKey"):
        vk, dk = _attr(mk, "validationKey") or "", _attr(mk, "decryptionKey") or ""
        if vk and not vk.lower().startswith("autogenerate"):
            fp = fingerprint(vk, dk)
            keys.append((fp, path))
            add("machinekey-hardcoded", "medium", "machineKey is hard-coded in this file (anyone who reads web.config or a backup can forge ViewState/auth tickets)",
                "Let each site auto-generate keys, or generate unique keys per site and protect the section (aspnet_regiis -pe). Use `iisguard fix machinekey` (M4).", fp)  # fmt: skip
        validation = (_attr(mk, "validation") or "").upper()
        if validation in ("SHA1", "MD5", "3DES"):
            add(
                "machinekey-weak-validation",
                "medium",
                f"machineKey validation={validation} is weak",
                'Use validation="HMACSHA256" or stronger.',
            )
        if (_attr(mk, "decryption") or "").upper() in ("DES", "3DES"):
            add("machinekey-weak-decryption", "medium", "machineKey uses DES/3DES", 'Use decryption="AES".')
    for pg in _walk(root, "pages"):
        if (_attr(pg, "enableViewStateMac") or "").lower() == "false":
            add(
                "viewstate-mac-disabled",
                "critical",
                "enableViewStateMac=false: ViewState is unauthenticated (deserialization attacks need no key)",
                'Remove the attribute or set enableViewStateMac="true".',
            )
        if (_attr(pg, "validateRequest") or "").lower() == "false":
            add(
                "validaterequest-off",
                "low",
                "validateRequest=false disables request validation for pages",
                "Enable it unless a page needs raw markup.",
            )
    for c in _walk(root, "compilation"):
        if (_attr(c, "debug") or "").lower() == "true":
            add("debug-enabled", "medium", "compilation debug=true", 'Set debug="false" in production.')
    for ce in _walk(root, "customErrors"):
        if (_attr(ce, "mode") or "").lower() == "off":
            add(
                "custom-errors-off",
                "medium",
                "customErrors mode=Off leaks stack traces",
                'Use mode="RemoteOnly" or "On".',
            )
    for tr in _walk(root, "trace"):
        if (_attr(tr, "enabled") or "").lower() == "true":
            sev = "high" if (_attr(tr, "localOnly") or "true").lower() == "false" else "medium"
            add("trace-enabled", sev, "ASP.NET tracing is enabled", 'Set <trace enabled="false" />.')
    for d in _walk(root, "directoryBrowse"):
        if (_attr(d, "enabled") or "").lower() == "true":
            add(
                "directory-browsing",
                "high",
                "directory browsing is enabled",
                'Set <directoryBrowse enabled="false" />.',
            )
    for hr in _walk(root, "httpRuntime"):
        mrl = _attr(hr, "maxRequestLength")
        if mrl and mrl.isdigit() and int(mrl) > 102400:
            add(
                "max-request-length-large",
                "low",
                f"httpRuntime maxRequestLength={mrl} KB (>100 MB)",
                "Lower it to what the app needs.",
            )
        if (_attr(hr, "enableVersionHeader") or "true").lower() != "false":
            add("version-header", "low", "X-AspNet-Version header is sent", 'Set enableVersionHeader="false".')
    has_limits = any(_attr(rl, "maxAllowedContentLength") for rl in _walk(root, "requestLimits"))
    if _walk(root, "system.webServer") and not has_limits:
        add("request-limits-missing", "low", "no requestFiltering/requestLimits maxAllowedContentLength set (default is ~30 MB)",
            "Set an explicit maxAllowedContentLength; for ASP.NET Core also set Kestrel MaxRequestBodySize / FormOptions and bound request decompression.")  # fmt: skip
    return out, keys


def audit_roots(roots: list[str]) -> ConfigAudit:
    res = ConfigAudit()
    seen_keys: dict[str, list[str]] = {}
    for r in roots:
        for dirpath, dirnames, filenames in os.walk(r, followlinks=False):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP]
            for fn in filenames:
                if fn.lower() != "web.config":
                    continue
                if res.files >= MAX_FILES:
                    return _finish(res, seen_keys)
                p = Path(dirpath) / fn
                res.files += 1
                try:
                    found, keys = audit_text(str(p), p.read_text(encoding="utf-8-sig", errors="replace"))
                except (ET.ParseError, ValueError, OSError) as e:
                    res.skipped.append(f"{p}: {e}")
                    continue
                res.findings += found
                for fp, path in keys:
                    seen_keys.setdefault(fp, []).append(path)
    return _finish(res, seen_keys)


def _finish(res: ConfigAudit, seen_keys: dict[str, list[str]]) -> ConfigAudit:
    for fp, paths in seen_keys.items():
        if len(set(paths)) > 1:
            for p in sorted(set(paths)):
                res.findings.append(ConfigFinding(p, "machinekey-shared", "high",
                                                  f"same machineKey is used by {len(set(paths))} web.config files (one leaked site compromises all)",
                                                  "Generate a unique machineKey per site/application.", fp))  # fmt: skip
    res.findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.id))
    return res
