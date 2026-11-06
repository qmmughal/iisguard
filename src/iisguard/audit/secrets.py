"""Find exposed secrets and risky files under a webroot. Matched values are ALWAYS masked in output.

Optional: confirm whether exposed files are reachable over HTTP. That check only runs against a host the user
explicitly confirms they own, is rate-limited, capped, never follows redirects and never stores response bodies.
"""

from __future__ import annotations

import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse

from iisguard.models import SEVERITY_RANK
from iisguard.webshell import SCRIPT_EXTS, SKIP_DIRS

TEXT_EXTS = {
    ".env", ".json", ".config", ".php", ".js", ".ts", ".yml", ".yaml", ".xml", ".ini", ".txt", ".py", ".cs", ".conf",
    ".properties", ".bak", ".old", ".orig", ".save", ".swp", ".sh", ".ps1", ".toml", ".cfg", ".inc", ".tpl", ".html", ".htm",
}  # fmt: skip
MAX_SCAN = 1024 * 1024


@dataclass(frozen=True)
class SecretPattern:
    id: str
    rx: re.Pattern[str]
    severity: str
    desc: str


def _p(id_: str, pat: str, sev: str, desc: str) -> SecretPattern:
    return SecretPattern(id_, re.compile(pat), sev, desc)


PATTERNS = [
    _p("anthropic-key", r"\bsk-ant-[A-Za-z0-9_\-]{32,}", "critical", "Anthropic API key"),
    _p("openai-key", r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}", "critical", "OpenAI API key"),
    _p("aws-access-key-id", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b", "high", "AWS access key id"),
    _p("aws-secret-key", r"(?i)aws_secret_access_key[\"'\s:=]+[A-Za-z0-9/+=]{40}\b", "critical", "AWS secret access key"),
    _p("stripe-live-key", r"\b[sr]k_live_[A-Za-z0-9]{16,}", "critical", "Stripe live secret/restricted key"),
    _p("stripe-test-key", r"\b[sr]k_test_[A-Za-z0-9]{16,}", "low", "Stripe test key"),
    _p("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}", "critical", "GitHub token"),
    _p("slack-token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "high", "Slack token"),
    _p("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", "critical", "private key block"),
    _p("plaintext-password", r"(?i)\b(?:password|pwd)\s*=\s*[^;\"'\s<>&]{6,}", "low", "plaintext password in config"),
]  # fmt: skip

EXPOSED_FILES = [
    (re.compile(r"(?:^|/)\.env(?!\.(?:example|sample|dist|template)$)(?:\.[\w.\-]+)?$", re.I), "high", "environment file", 0),
    (re.compile(r"(?:^|/)appsettings(?:\.[\w\-]+)?\.json$", re.I), "medium", "ASP.NET Core settings file in web tree", 0),
    (re.compile(r"(?:^|/)wp-config\.(?:php\.(?:bak|old|save|orig|txt|swp|dist)|php~|bak|old|txt|orig)$", re.I), "critical", "WordPress config backup", 0),
    (re.compile(r"(?:^|/)web\.config\.(?:bak|old|txt|orig|save)$", re.I), "high", "web.config backup", 0),
    (re.compile(r"(?:^|/)\.(?:htpasswd|npmrc|pypirc|netrc|dockercfg)$", re.I), "high", "credential file", 0),
    (re.compile(r"(?:^|/)\.aws/credentials$|(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)$|\.(?:pem|pfx|p12|key)$", re.I), "high", "key/credential material", 0),
    (re.compile(r"\.(?:sql|sql\.gz|dump|bak)$|(?:backup|dump|site|www|db)[\w\-]*\.(?:zip|tar\.gz|tgz|7z|rar)$", re.I), "medium", "possible backup or database dump", 1024),
]  # fmt: skip


@dataclass
class SecretFinding:
    path: str
    rel: str
    kind: str  # exposed-file | secret | git-directory
    id: str
    severity: str
    detail: str
    line: int = 0
    reachable: bool | None = None  # set by the optional HTTP check

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "kind": self.kind, "id": self.id, "severity": self.severity,
                "detail": self.detail, "line": self.line, "reachable": self.reachable}  # fmt: skip


def mask(value: str) -> str:
    """Never reveal more than a 4-character prefix and the length."""
    return f"{value[:4]}***[{len(value)} chars]"


def scan_text(text: str) -> list[tuple[SecretPattern, int, str]]:
    hits: list[tuple[SecretPattern, int, str]] = []
    for pat in PATTERNS:
        for m in pat.rx.finditer(text):
            hits.append((pat, text.count("\n", 0, m.start()) + 1, mask(m.group(0))))
            if len(hits) > 200:
                return hits
    return hits


def scan_webroot(roots: list[str], include_low: bool = False) -> list[SecretFinding]:
    out: list[SecretFinding] = []
    for r in roots:
        root = Path(r)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if ".git" in dirnames:
                rel = (Path(dirpath) / ".git").relative_to(root).as_posix()
                out.append(SecretFinding(str(Path(dirpath) / ".git"), rel, "git-directory", "git-directory", "high",
                                         "repository metadata inside the web root (source and history can be downloaded if served)"))  # fmt: skip
            dirnames[:] = [d for d in dirnames if d.lower() not in (SKIP_DIRS - {".git"}) and d != ".git"]
            for fn in filenames:
                p = Path(dirpath) / fn
                rel = p.relative_to(root).as_posix()
                for rx, sev, desc, min_size in EXPOSED_FILES:
                    if rx.search(rel):
                        try:
                            if p.stat().st_size < min_size:
                                break  # tiny placeholder, not a real dump
                        except OSError:
                            break
                        out.append(SecretFinding(str(p), rel, "exposed-file", desc.replace(" ", "-"), sev, desc))
                        break
                ext = p.suffix.lower()
                if ext not in TEXT_EXTS and not fn.lower().startswith(".env"):
                    continue
                try:
                    if p.is_symlink() or p.stat().st_size > MAX_SCAN:
                        continue
                    data = p.read_bytes()
                except OSError:
                    continue
                if b"\x00" in data[:2048]:
                    continue
                for pat, line, masked in scan_text(data.decode("latin-1")):
                    sev = pat.severity
                    note = ""
                    if ext in SCRIPT_EXTS and SEVERITY_RANK[sev] > 1:
                        sev, note = (
                            "low",
                            " (inside server-side code: not served raw, still rotate if it was ever shared/committed)",
                        )
                    out.append(SecretFinding(str(p), rel, "secret", pat.id, sev, f"{pat.desc}: {masked}{note}", line))
    floor = 0 if include_low else SEVERITY_RANK["medium"]
    out = [f for f in out if SEVERITY_RANK[f.severity] >= floor]
    out.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line))
    return out


# ------------------------------------------------------------------ optional reachability check
Fetcher = Callable[[str], int]
MAX_URL_CHECKS = 50


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: object, **k: object) -> None:
        return None


def http_status(url: str) -> int:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "iisguard-exposure-check (+https://github.com/qmmughal/iisguard)",
            "Range": "bytes=0-255",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=8) as resp:
            resp.read(256)  # read a few bytes and discard them
            return int(resp.status)
    except urllib.error.HTTPError as e:
        return int(e.code)
    except (urllib.error.URLError, OSError):
        return 0


def check_reachable(
    findings: list[SecretFinding], base_url: str, confirmed_owner: str,
    fetch: Fetcher = http_status, delay: float = 0.5, sleep: Callable[[float], None] = time.sleep,
) -> int:  # fmt: skip
    """Mark findings reachable over HTTP. Only runs for a host the user confirmed they own."""
    u = urlparse(base_url)
    host = (u.hostname or "").lower()
    if u.scheme not in ("http", "https") or not host:
        raise ValueError("base URL must be http(s)://host")
    if host != confirmed_owner.strip().lower():
        raise ValueError(f"refusing to probe {host!r}: --confirm-owner must be exactly the host you own")
    base = base_url.rstrip("/")
    checked = 0
    for f in findings:
        servable = f.kind in ("exposed-file", "git-directory") or Path(f.rel).suffix.lower() not in SCRIPT_EXTS
        if not servable or checked >= MAX_URL_CHECKS:
            continue
        rel = ".git/config" if f.kind == "git-directory" else f.rel
        status = fetch(f"{base}/{quote(rel)}")
        f.reachable = status in (200, 206)
        checked += 1
        sleep(delay)
    return checked
