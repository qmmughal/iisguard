"""Deterministic synthetic logs. Markers are harmless strings; no real payloads.

Attacker IPs are arbitrary public-range addresses used only as text.
"""

from __future__ import annotations

import calendar
import random
from pathlib import Path
from typing import NamedTuple

BASE = calendar.timegm((2026, 11, 7, 10, 0, 0))
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

A_PHP2SHELL = "45.9.1.10"
A_WP = "45.9.1.11"
A_VIEWSTATE = "45.9.1.12"
A_SHELL_C2 = "45.9.1.13"
A_SHAREPOINT = "45.9.1.14"
A_EXCHANGE = "45.9.1.15"
A_BRUTE = "45.9.1.20"
A_FLOOD = "45.9.1.30"
A_SCANNER = "45.9.1.31"
ADMIN_IP = "45.9.1.99"
SPRAY_IPS = [f"185.100.{n}.{h}" for n in (1, 2) for h in range(10, 25)]  # 30 IPs, two /24s


class Ev(NamedTuple):
    ts: int
    ip: str
    method: str
    path: str
    query: str
    status: int
    ua: str


def clean_events() -> list[Ev]:
    rnd = random.Random(7)
    ips = [f"91.{i}.{i + 3}.{i + 7}" for i in range(20, 40)]
    pages = ["/", "/about", "/products", "/contact", "/blog/hello-world", "/wp-login.php", "/login"]
    out: list[Ev] = []
    for i in range(400):
        ip = rnd.choice(ips)
        t = BASE + i * 5
        out.append(Ev(t, ip, "GET", rnd.choice(pages), "", 200, UA_BROWSER))
        if i % 9 == 0:  # page assets
            for asset in ("/static/app.css", "/static/app.js", "/img/logo.png"):
                out.append(Ev(t, ip, "GET", asset, "v=3", 200, UA_BROWSER))
        if i % 40 == 0:
            out.append(Ev(t, ip, "GET", "/favicon.ico", "", 404, UA_BROWSER))
        if i % 50 == 0:  # a normal user logging in, 2 attempts
            out.append(Ev(t, ip, "POST", "/login", "", 302, UA_BROWSER))
            out.append(Ev(t + 20, ip, "POST", "/login", "", 302, UA_BROWSER))
    out.append(
        Ev(
            BASE + 100,
            "66.249.66.1",
            "GET",
            "/robots.txt",
            "",
            200,
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
        )
    )
    out.append(Ev(BASE + 101, "91.50.1.1", "POST", "/api/orders", "", 201, UA_BROWSER))
    out.append(Ev(BASE + 102, "91.50.1.2", "GET", "/__VIEWSTATE-docs", "", 200, UA_BROWSER))
    out.append(Ev(BASE + 103, "91.50.1.3", "GET", "/search", "q=union+station+timetable", 200, UA_BROWSER))
    out.append(Ev(BASE + 104, "91.50.1.4", "GET", "/page.aspx", "__VIEWSTATE=abc&__EVENTTARGET=x", 200, UA_BROWSER))
    return sorted(out)


def attack_events() -> list[Ev]:
    t = BASE + 2000
    ev: list[Ev] = []
    ev.append(
        Ev(
            t,
            A_PHP2SHELL,
            "POST",
            "/index.php",
            "PHP_SESSION_UPLOAD_PROGRESS=harmless-marker",
            200,
            "python-requests/2.31",
        )
    )
    ev.append(Ev(t + 1, A_WP, "GET", "/wp-admin/setup-config.php", "step=1", 404, UA_BROWSER))
    ev.append(Ev(t + 2, A_WP, "GET", "/wp-content/upgrade/wordpress-6.8/index.php", "", 404, UA_BROWSER))
    ev.append(Ev(t + 3, A_VIEWSTATE, "GET", "/default.aspx", "__VIEWSTATE=" + "A" * 1500, 500, UA_BROWSER))
    ev.append(Ev(t + 4, A_SHELL_C2, "POST", "/images/logo.png", "", 200, UA_BROWSER))
    ev.append(Ev(t + 5, A_SHELL_C2, "GET", "/UpdateChecker.aspx", "", 200, UA_BROWSER))
    ev.append(
        Ev(
            t + 6,
            A_SHAREPOINT,
            "POST",
            "/_layouts/15/ToolPane.aspx",
            "DisplayMode=Edit&a=/ToolPane.aspx",
            200,
            UA_BROWSER,
        )
    )
    ev.append(Ev(t + 7, A_EXCHANGE, "GET", "/owa/auth/shell1.aspx", "", 200, UA_BROWSER))
    ev.append(Ev(t + 8, A_PHP2SHELL, "GET", "/wp-content/uploads/2026/11/x.php", "", 200, UA_BROWSER))
    for i in range(25):  # brute force from one IP
        ev.append(Ev(t + 10 + i * 4, A_BRUTE, "POST", "/wp-login.php", "", 200, UA_BROWSER))
    for i, ip in enumerate(SPRAY_IPS):  # distributed spray, 2 attempts each
        ev.append(Ev(t + 20 + i * 3, ip, "POST", "/wp-login.php", "", 200, UA_BROWSER))
        ev.append(Ev(t + 120 + i * 3, ip, "POST", "/wp-login.php", "", 200, UA_BROWSER))
    for i in range(400):  # flood: 400 requests in 4 seconds
        ev.append(Ev(t + 300 + i // 100, A_FLOOD, "GET", "/search", f"q={i}", 200, UA_BROWSER))
    probes = ["/.env", "/.git/config", "/wp-config.php.bak", "/backup.zip", "/admin", "/phpmyadmin/index.php"]
    for i in range(40):  # scanner with scanner UA producing many 404s
        ev.append(
            Ev(
                t + 400 + i,
                A_SCANNER,
                "GET",
                probes[i % len(probes)] + ("" if i < 6 else f"/{i}"),
                "",
                404,
                "sqlmap/1.7.2#stable",
            )
        )
    ev.append(Ev(t + 450, A_PHP2SHELL, "GET", "/a", "id=1 union select 1,2", 200, UA_BROWSER))
    ev.append(
        Ev(
            t + 500,
            ADMIN_IP,
            "POST",
            "/index.php",
            "PHP_SESSION_UPLOAD_PROGRESS=harmless-marker",
            200,
            UA_BROWSER,
        )
    )
    return sorted(ev)


def php_error_lines() -> list[str]:
    lines = [
        "[07-Nov-2026 10:00:00 UTC] PHP Notice:  Undefined variable $x in /var/www/a.php on line 3",
        "[07-Nov-2026 10:00:01 UTC] PHP Warning:  Undefined array key in /var/www/a.php on line 4",
    ]
    for i in range(14):  # burst of fatals
        lines.append(
            f"[07-Nov-2026 10:20:{i:02d} UTC] PHP Fatal error:  Uncaught Error: Call to undefined function in /var/www/b.php:{i}"
        )
        lines.append("Stack trace:")
        lines.append("#0 {main}")
    lines.append(
        "[07-Nov-2026 10:21:30 UTC] WARNING: [pool www] child 99 exited on signal 11 (SIGSEGV) after 10.2 seconds"
    )
    return lines


def apache_error_lines() -> list[str]:
    return [
        f"[Sat Nov 07 10:20:{i:02d}.123456 2026] [php:error] [pid 12] [client 45.9.1.10:5{i:04d}] PHP Fatal error:  boom in /var/www/c.php"
        for i in range(12)
    ]


# --------------------------------------------------------------------- writers
def write_iis(path: Path, events: list[Ev]) -> None:
    head = [
        "#Software: Microsoft Internet Information Services 10.0",
        "#Version: 1.0",
        "#Date: 2026-11-07 00:00:00",
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken",
    ]
    rows = []
    for e in events:
        tm = calendar.timegm((2026, 11, 7, 0, 0, 0))
        s = e.ts - tm
        rows.append(
            f"2026-11-07 {s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d} 10.0.0.5 {e.method} {e.path} "
            f"{e.query.replace(' ', '+') or '-'} 443 - {e.ip} {e.ua.replace(' ', '+')} - {e.status} 0 0 12"
        )
    path.write_text("\n".join(head + rows) + "\n", encoding="latin-1")


def write_combined(path: Path, events: list[Ev], tz: str = "+0000") -> None:
    sign = -1 if tz[0] == "-" else 1
    off = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
    rows = []
    for e in events:
        loc = e.ts + off
        h, m, s = loc % 86400 // 3600, loc % 3600 // 60, loc % 60
        target = e.path + ("?" + e.query.replace(" ", "%20") if e.query else "")
        rows.append(
            f'{e.ip} - - [07/Nov/2026:{h:02d}:{m:02d}:{s:02d} {tz}] "{e.method} {target} HTTP/1.1" {e.status} 512 "-" "{e.ua}"'
        )
    path.write_text("\n".join(rows) + "\n", encoding="latin-1")


def write_json(path: Path, events: list[Ev]) -> None:
    import json

    rows = [
        json.dumps(
            {
                "remote_addr": e.ip,
                "time": e.ts,
                "request_method": e.method,
                "request_uri": e.path + ("?" + e.query if e.query else ""),
                "status": e.status,
                "http_user_agent": e.ua,
            }
        )
        for e in events
    ]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
