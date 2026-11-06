"""File hunter: web-shell signatures, masquerading files, scripts in upload folders, risky handler config.

Defensive and read-only. It only reads files (bounded size) and reports; moving files is `quarantine` (M4).
Scoring: each indicator adds points; >=40 is reported (medium), >=70 high, >=90 critical.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

PHP_EXTS = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".pht", ".phar", ".inc"}
ASP_EXTS = {".asp", ".aspx", ".ashx", ".asmx", ".ascx", ".asa", ".cer", ".cshtml", ".vbhtml", ".axd", ".svc"}
JSP_EXTS = {".jsp", ".jspx", ".jspf", ".jsw", ".jsv"}
SCRIPT_EXTS = PHP_EXTS | ASP_EXTS | JSP_EXTS
DISGUISE_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".bmp",
    ".webp",
    ".svg",
    ".txt",
    ".pdf",
    ".css",
    ".dat",
    ".bak",
    ".tmp",
}
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__"}
UPLOAD_DIR_RX = re.compile(
    r"(?:^|[\\/])(?:uploads?|upload_files|userfiles|user_uploads|attachments|media|images?|img|files|tmp|temp)(?:[\\/]|$)",
    re.I,
)
MAX_READ = 2 * 1024 * 1024
HEAD_READ = 64 * 1024

OWA_AUTH_OK = {
    "logon.aspx", "errorfe.aspx", "error.aspx", "logoff.aspx", "expiredpassword.aspx", "redirsuiteservice.aspx",
    "frame.aspx", "getidtoken.aspx", "outlook.aspx", "redir.aspx", "timeout.aspx", "trace.aspx",
}  # fmt: skip

NAME_RX = re.compile(
    r"^(?:c99|c100|r57|wso\d*|b374k|alfa|webshell|indoxploit|filesman|updatechecker|spinstall\d*|shell\d*|cmd|"
    r"mini|china|ant|antsword|godzilla|behinder|bluebeam)\.(?:php\d?|phtml|aspx?|ashx|asmx|jsp|jspx)$",
    re.I,
)
DOUBLE_EXT_RX = re.compile(
    r"\.(?:png|jpe?g|gif|ico|bmp|txt|pdf)\.(?:aspx?|ashx|php\d?|phtml|jsp)$|\.(?:aspx?|ashx|php\d?|jsp);\.?(?:png|jpe?g|gif|txt)$",
    re.I,
)
SCRIPT_IN_DATA_RX = re.compile(
    rb"<\?php\s|<\?=\s|<%@\s*(?:Page|Control|WebHandler|Assembly)\b|<script\s+runat\s*=\s*[\"']server", re.I
)


@dataclass(frozen=True)
class Sig:
    id: str
    group: str  # php | asp | jsp
    rx: re.Pattern[str]
    score: int
    desc: str


def _s(id_: str, group: str, pat: str, score: int, desc: str) -> Sig:
    return Sig(id_, group, re.compile(pat, re.I | re.S), score, desc)


_IN = r"\$_(?:POST|GET|REQUEST|COOKIE|SERVER)"
SIGS: list[Sig] = [
    _s("php-eval-decode-chain", "php", r"\beval\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode)\s*\(", 70, "eval() of a decoded string"),
    _s("php-eval-input", "php", rf"\beval\s*\(\s*(?:@\s*)?{_IN}", 95, "eval() of request input"),
    _s("php-assert-input", "php", rf"\bassert\s*\(\s*(?:@\s*)?{_IN}", 90, "assert() of request input"),
    _s("php-exec-input", "php", rf"\b(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?{_IN}", 95, "command execution from request input"),
    _s("php-call-input", "php", rf"{_IN}\s*\[[^\]]{{1,40}}\]\s*\(", 85, "request input called as a function"),
    _s("php-decode-chain", "php", r"\b(?:gzinflate|gzuncompress|gzdecode)\s*\(\s*(?:@\s*)?base64_decode\s*\(", 60, "nested decode chain"),
    _s("php-create-function", "php", r"\bcreate_function\s*\(", 40, "create_function() (removed in PHP 8; legacy shells)"),
    _s("php-preg-e", "php", r"preg_replace\s*\(\s*['\"]/[^'\"]*/[a-z]*e[a-z]*['\"]", 70, "preg_replace /e modifier"),
    _s("php-big-b64", "php", r"base64_decode\s*\(\s*['\"][A-Za-z0-9+/=\s]{300,}['\"]", 40, "large embedded base64 blob"),
    _s("asp-assembly-load-b64", "asp", r"Assembly\s*\.\s*Load\s*\(\s*(?:System\s*\.\s*)?Convert\s*\.\s*FromBase64String", 85, "Assembly.Load of base64 data (in-memory loader)"),
    _s("asp-eval-request", "asp", r"\b(?:eval|Execute(?:Global)?)\s*\(?\s*(?:Request|request)\b", 90, "eval/Execute of request data"),
    _s("asp-process-start", "asp", r"\bProcess\s*\.\s*Start\b|\bProcessStartInfo\b", 40, "starts processes"),
    _s("asp-request-input", "asp", r"\bRequest\s*(?:\.\s*(?:Form|QueryString|Params|Item|Headers|Cookies)|\[)", 10, "reads request data"),
    _s("asp-cmd-c", "asp", r"cmd(?:\.exe)?[\"']?\s*,?\s*[\"']?\s*/c\b", 40, "cmd /c"),
    _s("asp-codedom", "asp", r"CompileAssemblyFromSource|CSharpCodeProvider|VBCodeProvider", 40, "compiles code at runtime"),
    _s("asp-big-b64", "asp", r"FromBase64String\s*\(\s*\"[A-Za-z0-9+/=]{300,}\"", 40, "large embedded base64 blob"),
    _s("jsp-runtime-exec", "jsp", r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", 60, "Runtime.exec"),
    _s("jsp-request-param", "jsp", r"request\s*\.\s*getParameter\s*\(", 10, "reads request parameters"),
    _s("jsp-defineclass", "jsp", r"\bdefineClass\s*\(", 60, "defines classes from bytes (loader)"),
    _s("jsp-processbuilder", "jsp", r"\bnew\s+ProcessBuilder\s*\(", 30, "ProcessBuilder"),
]  # fmt: skip

COMBOS: list[tuple[str, str, int, str]] = [
    ("asp-process-start", "asp-request-input", 50, "request input reaches process start"),
    ("jsp-runtime-exec", "jsp-request-param", 30, "request input reaches Runtime.exec"),
    ("jsp-processbuilder", "jsp-request-param", 40, "request input reaches ProcessBuilder"),
    ("jsp-defineclass", "jsp-request-param", 30, "request input reaches defineClass"),
]
LONG_BLOB_RX = re.compile(r"[A-Za-z0-9+/=]{600,}")
HANDLER_CFG_RX = re.compile(
    r"(?:AddHandler|SetHandler|AddType)\s+[^\r\n]*(?:php|cgi|fcgi)[^\r\n]*\.(?:png|jpe?g|gif|ico|txt|css)\b"
    r"|<add\s[^>]*path\s*=\s*[\"']\*\.(?:png|jpe?g|gif|ico|txt|css)[\"'][^>]*(?:ManagedPipelineHandler|FastCgiModule|IsapiModule|CgiModule|PHP)",
    re.I,
)
PREPEND_RX = re.compile(r"^\s*(?:php_(?:admin_)?value\s+)?(auto_(?:prepend|append)_file)\b[\s=]+(\S.*)$", re.I | re.M)


@dataclass
class HuntFinding:
    path: str
    score: int
    severity: str
    reasons: list[str] = field(default_factory=list)
    sha256: str = ""
    size: int = 0
    mtime: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "score": self.score, "severity": self.severity, "reasons": self.reasons,
                "sha256": self.sha256, "size": self.size, "mtime": self.mtime}  # fmt: skip


def severity_for(score: int) -> str:
    return "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _group_for(ext: str) -> str | None:
    return "php" if ext in PHP_EXTS else "asp" if ext in ASP_EXTS else "jsp" if ext in JSP_EXTS else None


def _is_silence_stub(text: str) -> bool:
    t = re.sub(r"\s+", "", text.lower())
    return len(t) < 120 and ("silenceisgolden" in t or t in ("<?php", "<?php?>", ""))


def analyze_content(text: str, group: str | None) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    hit: set[str] = set()
    groups = [group] if group else ["php", "asp", "jsp"]
    for sig in SIGS:
        if sig.group in groups and sig.rx.search(text):
            hit.add(sig.id)
            out.append((f"{sig.id}: {sig.desc}", sig.score))
    for a, b, bonus, desc in COMBOS:
        if a in hit and b in hit:
            out.append((f"combo: {desc}", bonus))
    longest = max((len(line) for line in text.splitlines()), default=0)
    if longest >= 500:
        line = max(text.splitlines(), key=len)
        ws = sum(c.isspace() for c in line) / len(line)
        if shannon_entropy(line) >= 5.0 and ws < 0.02:
            out.append(("high-entropy-long-line: probable encoded/obfuscated blob", 25))
    elif LONG_BLOB_RX.search(text):
        out.append(("long-encoded-blob: 600+ char base64-like run", 25))
    return out


def _read(path: Path, limit: int) -> bytes | None:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return None


def analyze_file(
    path: Path, since_days: float | None = None, now: float | None = None, root: Path | None = None
) -> HuntFinding | None:
    try:
        st = path.lstat()
    except OSError:
        return None
    if not path.is_file() or path.is_symlink():
        return None
    name = path.name.lower()
    ext = path.suffix.lower()
    pstr = str(path)
    # Location rules look at the path RELATIVE to the scanned root, so parents like ...\Temp\ do not count.
    try:
        relp = str(path.relative_to(root)) if root is not None and root.is_dir() else path.name
    except ValueError:
        relp = pstr
    norm = "/" + relp.replace("\\", "/").lower()
    reasons: list[tuple[str, int]] = []
    in_upload = bool(UPLOAD_DIR_RX.search(relp))
    recent = since_days is not None and ((now or time.time()) - st.st_mtime) <= since_days * 86400

    if NAME_RX.match(name):
        reasons.append(("known web-shell file name", 70))
    if DOUBLE_EXT_RX.search(name):
        reasons.append(("script disguised with an image/text extension", 90))

    group = _group_for(ext)
    if group:
        data = _read(path, MAX_READ)
        if data is None:
            return None
        text = data.decode("latin-1")
        stub = _is_silence_stub(text)
        if not stub:
            reasons += analyze_content(text, group)
            if in_upload:
                wp = "/wp-content/uploads/" in norm
                reasons.append(("script file inside an upload/media folder", 80 if wp else 60))
        if ext == ".aspx" and "/owa/auth/" in norm and name not in OWA_AUTH_OK:
            reasons.append(("unexpected .aspx under /owa/auth/ (Exchange)", 60))
        if ext in ASP_EXTS and "/_layouts/" in norm and recent:
            reasons.append(("recently changed script under SharePoint _layouts", 40))
        if recent and reasons:
            reasons.append(("modified recently", 10))
    elif ext in DISGUISE_EXTS:
        head = _read(path, HEAD_READ)
        if head is None:
            return None
        if SCRIPT_IN_DATA_RX.search(head):
            reasons.append(("script code inside a non-script (image/text) file", 80))
            if head[:4] in (b"GIF8", b"\x89PNG", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1"):
                reasons.append(("image/script polyglot header", 10))
    elif name == ".user.ini" or name == ".htaccess" or name == "web.config":
        data = _read(path, 256 * 1024)
        if data is None:
            return None
        text = data.decode("latin-1")
        for m in PREPEND_RX.finditer(text):
            reasons.append(
                (f"{m.group(1).lower()} set to {m.group(2).strip()[:60]!r} (code injected into every PHP request)", 70)
            )
        if name != ".user.ini" and HANDLER_CFG_RX.search(text):
            reasons.append(("handler mapping makes image/text files execute as scripts", 80))

    score = min(100, sum(s for _, s in reasons))
    if score < 40:
        return None
    sha = ""
    data_all = _read(path, MAX_READ)
    if data_all is not None:
        sha = hashlib.sha256(data_all).hexdigest()
    return HuntFinding(pstr, score, severity_for(score), [r for r, _ in reasons], sha, st.st_size, st.st_mtime)


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
        for fn in filenames:
            yield Path(dirpath) / fn


def hunt(roots: list[str], since_days: float | None = None, min_score: int = 40) -> list[HuntFinding]:
    findings: list[HuntFinding] = []
    now = time.time()
    for r in roots:
        for p in iter_files(Path(r)):
            f = analyze_file(p, since_days, now, Path(r))
            if f and f.score >= min_score:
                findings.append(f)
    findings.sort(key=lambda f: (-f.score, f.path))
    return findings
