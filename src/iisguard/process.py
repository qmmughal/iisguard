"""Web-server process anomalies: a web worker spawning shells or recon/download tools.

Sources (all read-only): exported Windows Security 4688 / Sysmon 1 XML, auditd text, and a live process list
(`ps` on Linux, a read-only CIM query on Windows). Note: this catches child processes only. In-memory implants
(Godzilla/BLUEBEAM inside w3wp.exe) that never spawn a process need EDR or memory forensics; see docs.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from iisguard.models import SEVERITY_RANK

PowershellRunner = Callable[[list[str]], str]

WEB_PARENTS = re.compile(
    r"^(?:w3wp|php-cgi|php-fpm[\d.]*|php\d[\d.]*-fpm|httpd|apache2?|nginx|tomcat\d*w?|catalina|"
    r"lsws|litespeed|frankenphp|caddy|uwsgi|gunicorn)(?:\.exe)?$",
    re.I,
)
# Admin-run interpreters (php CLI, dotnet) are deliberately not treated as web parents.
SHELLS = re.compile(
    r"^(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|msiexec|certutil|bitsadmin|curl|wget|"
    r"bash|sh|dash|zsh|ksh|nc|ncat|netcat|socat|python[\d.]*|perl|ruby)(?:\.exe)?$",
    re.I,
)
RECON = re.compile(
    r"^(?:whoami|net1?|nltest|systeminfo|ipconfig|ifconfig|tasklist|quser|query|klist|arp|route|netstat|"
    r"nslookup|dsquery|wmic|sc|schtasks|reg|id|uname|hostname|ls|cat|ps)(?:\.exe)?$",
    re.I,
)
DOWNLOAD_CMD = re.compile(r"(?:certutil.*-urlcache|bitsadmin.*/transfer|invoke-webrequest|downloadstring|downloadfile|"
                          r"\b(?:curl|wget)\b.*https?://|-enc(?:odedcommand)?\s|frombase64string|iex\s*\(|\|\s*(?:ba)?sh\b)", re.I)  # fmt: skip
ALLOW_CMD = re.compile(r"sendmail|/usr/sbin/exim|msmtp|wkhtmltopdf|git\s", re.I)  # legit helpers; extendable


@dataclass
class ProcEvent:
    pid: int = 0
    ppid: int = 0
    image: str = ""
    parent_image: str = ""
    cmdline: str = ""
    user: str = ""
    ts: float = 0.0
    source: str = ""

    @staticmethod
    def base(path: str) -> str:
        return re.split(r"[\\/]", path.strip())[-1] if path else ""


@dataclass
class ProcFinding:
    severity: str
    rule: str
    parent: str
    child: str
    cmdline: str
    user: str
    ts: float
    source: str
    detail: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            k: getattr(self, k)
            for k in ("severity", "rule", "parent", "child", "cmdline", "user", "ts", "source", "detail")
        }


def classify(ev: ProcEvent, allow: re.Pattern[str] = ALLOW_CMD) -> ProcFinding | None:
    parent = ProcEvent.base(ev.parent_image).rstrip(":")  # ps titles look like "php-fpm: pool www"
    child = ProcEvent.base(ev.image).rstrip(":")
    if not parent or not child or not WEB_PARENTS.match(parent):
        return None
    if allow.search(ev.cmdline) or allow.search(ev.image):
        return None
    is_shell = bool(SHELLS.match(child))
    is_recon = bool(RECON.match(child))
    if not (is_shell or is_recon):
        return None
    dl = bool(DOWNLOAD_CMD.search(ev.cmdline))
    if dl:
        sev, rule, why = "critical", "web-worker-download-or-encoded", "downloads, encoded commands or pipe-to-shell"
    elif is_shell:
        sev, rule, why = "high", "web-worker-spawned-shell", "interpreter/shell started by a web worker"
    else:
        sev, rule, why = "high", "web-worker-spawned-recon", "reconnaissance tool started by a web worker"
    return ProcFinding(sev, rule, parent, child, ev.cmdline[:300], ev.user, ev.ts, ev.source, why)


# ------------------------------------------------------------------ parsers
def _ts(text: str) -> float:
    try:
        t = re.sub(r"(\.\d{6})\d+", r"", text.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(t)
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()
    except ValueError:
        return 0.0


def parse_event_xml(text: str) -> list[ProcEvent]:
    """Windows Security 4688 and Sysmon EventID 1 records, as exported XML (one or many <Event> elements)."""
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("refusing XML with a DOCTYPE/ENTITY declaration")
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    root = ET.fromstring(f"<Events>{body}</Events>") if not body.lstrip().startswith("<Events") else ET.fromstring(body)
    out: list[ProcEvent] = []
    for ev in root.iter():
        if not ev.tag.endswith("Event") or ev.tag.endswith("}EventData"):
            continue
        sysel = next((c for c in ev if c.tag.endswith("System")), None)
        if sysel is None:
            continue
        eid = next((c.text or "" for c in sysel if c.tag.endswith("EventID")), "")
        tc = next((c.get("SystemTime", "") for c in sysel if c.tag.endswith("TimeCreated")), "")
        data = {d.get("Name", ""): (d.text or "") for e in ev if e.tag.endswith("EventData") for d in e}
        if eid.strip() == "4688":
            out.append(ProcEvent(_pid(data.get("NewProcessId", "")), _pid(data.get("ProcessId", "")), data.get("NewProcessName", ""),
                                 data.get("ParentProcessName", "") or data.get("CreatorProcessName", ""), data.get("CommandLine", ""),
                                 data.get("SubjectUserName", ""), _ts(tc), "security-4688"))  # fmt: skip
        elif eid.strip() == "1" and "Image" in data:
            out.append(ProcEvent(_pid(data.get("ProcessId", "")), _pid(data.get("ParentProcessId", "")), data.get("Image", ""),
                                 data.get("ParentImage", ""), data.get("CommandLine", ""), data.get("User", ""), _ts(tc), "sysmon-1"))  # fmt: skip
    return out


def _pid(v: str) -> int:
    try:
        return int(v, 0) if v else 0
    except ValueError:
        return 0


_AUD_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def parse_auditd(lines: Iterable[str]) -> list[ProcEvent]:
    """auditd SYSCALL records (execve). Parent image is resolved from earlier records by pid."""
    exe_by_pid: dict[int, str] = {}
    out: list[ProcEvent] = []
    for line in lines:
        if "type=SYSCALL" not in line:
            continue
        kv = {k: v.strip('"') for k, v in _AUD_KV.findall(line)}
        pid, ppid = _pid(kv.get("pid", "")), _pid(kv.get("ppid", ""))
        exe = kv.get("exe", "") or kv.get("comm", "")
        if pid:
            exe_by_pid[pid] = exe
        out.append(
            ProcEvent(pid, ppid, exe, exe_by_pid.get(ppid, ""), kv.get("comm", ""), kv.get("auid", ""), 0.0, "auditd")
        )
    return [e for e in out if e.parent_image or e.ppid]


def parse_ps(text: str) -> list[ProcEvent]:
    """`ps -eo pid=,ppid=,user=,args=` output -> events with parent images from the same snapshot."""
    rows: dict[int, tuple[int, str, str]] = {}
    for line in text.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        rows[int(parts[0])] = (int(parts[1]), parts[2], parts[3])
    out: list[ProcEvent] = []
    for pid, (ppid, user, args) in rows.items():
        parent_args = rows.get(ppid, (0, "", ""))[2]
        try:
            exe = shlex.split(args)[0]
            pexe = shlex.split(parent_args)[0] if parent_args else ""
        except ValueError:
            exe, pexe = args.split()[0], parent_args.split()[0] if parent_args else ""
        out.append(ProcEvent(pid, ppid, exe, pexe, args, user, 0.0, "ps"))
    return out


def parse_cim_json(text: str) -> list[ProcEvent]:
    data = json.loads(text) if text.strip() else []
    rows = data if isinstance(data, list) else [data]
    names = {int(r["ProcessId"]): str(r.get("Name") or "") for r in rows if "ProcessId" in r}
    return [
        ProcEvent(int(r["ProcessId"]), int(r.get("ParentProcessId") or 0), str(r.get("Name") or ""),
                  names.get(int(r.get("ParentProcessId") or 0), ""), str(r.get("CommandLine") or ""), "", 0.0, "cim")
        for r in rows if "ProcessId" in r
    ]  # fmt: skip


def live_events(runner: Callable[[list[str]], str]) -> list[ProcEvent]:
    if sys.platform == "win32":
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
               "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress"]  # fmt: skip
        return parse_cim_json(runner(cmd))
    return parse_ps(runner(["ps", "-eo", "pid=,ppid=,user=,args="]))


def detect(events: Iterable[ProcEvent]) -> list[ProcFinding]:
    found = [f for f in (classify(e) for e in events) if f]
    found.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.ts))
    return found
