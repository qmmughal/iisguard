"""External exposure check for a site YOU OWN. Read-only (GET), rate-limited, capped, no redirects followed.

It refuses to run unless --confirm-owner exactly equals the host in the URL. It never tries to discover or guess an
origin server: the origin-direct check only runs if you hand it your own origin IP.
"""

from __future__ import annotations

import http.client
import ipaddress
import random
import socket
import ssl
import string
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from iisguard.firewall.safety import bundled_cdn_ranges
from iisguard.report.model import Finding

MAX_REQUESTS = 40
UA = "iisguard-exposure-check (+https://github.com/qmmughal/iisguard)"
DIR_PATHS = ["/", "/uploads/", "/images/", "/wp-content/uploads/", "/files/", "/assets/", "/backup/"]
DIR_MARKERS = ("Index of /", "Directory listing for", "[To Parent Directory]", "Parent Directory</a>")
SENSITIVE = ["/.env", "/.git/config", "/web.config", "/wp-config.php.bak", "/appsettings.json", "/phpinfo.php", "/server-status",
             "/elmah.axd", "/trace.axd"]  # fmt: skip
PANELS = ["/wp-login.php", "/wp-admin/", "/administrator/", "/phpmyadmin/", "/owa/", "/ecp/", "/_layouts/15/start.aspx",
          "/manager/html", "/admin/"]  # fmt: skip
BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: object, **k: object) -> None:
        return None


def http_get(url: str, timeout: float = 8.0) -> Response | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return Response(r.status, list(r.headers.items()), r.read(2048))
    except urllib.error.HTTPError as e:
        return Response(e.code, list(e.headers.items()), e.read(2048))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def origin_get(ip: str, host: str, path: str = "/", timeout: float = 8.0) -> Response | None:
    """GET https://<ip>/ with SNI and Host set to the site name. Certificate is not verified: we only learn if it answers."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        conn = http.client.HTTPSConnection(ip, 443, timeout=timeout, context=ctx)
        conn.sock = ctx.wrap_socket(sock, server_hostname=host)
        conn.request("GET", path, headers={"Host": host, "User-Agent": UA})
        r = conn.getresponse()
        resp = Response(r.status, r.getheaders(), r.read(2048))
        conn.close()
        return resp
    except (OSError, http.client.HTTPException):
        return None


def tls_info(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as s,
            ctx.wrap_socket(s, server_hostname=host) as t,
        ):
            cert = t.getpeercert() or {}
            exp = ssl.cert_time_to_seconds(str(cert["notAfter"])) if cert.get("notAfter") else 0
            return {
                "version": t.version(),
                "days_left": int((exp - time.time()) // 86400) if exp else None,
                "error": "",
            }
    except ssl.SSLCertVerificationError as e:
        return {"version": "", "days_left": None, "error": f"certificate not trusted: {e.verify_message}"}
    except (OSError, ssl.SSLError) as e:
        return {"version": "", "days_left": None, "error": str(e)[:150]}


def resolve(host: str) -> list[str]:
    try:
        return sorted({str(i[4][0]) for i in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except OSError:
        return []


def cdn_for(ips: list[str]) -> str:
    for name, ranges in bundled_cdn_ranges().items():
        nets = [ipaddress.ip_network(r) for r in ranges]
        for ip in ips:
            a = ipaddress.ip_address(ip)
            if any(a.version == n.version and a in n for n in nets):
                return name
    return ""


def check(
    url: str,
    confirm_owner: str,
    origin_ip: str | None = None,
    get: Callable[[str], Response | None] = http_get,
    tls: Callable[[str], dict[str, Any]] = tls_info,
    dns: Callable[[str], list[str]] = resolve,
    origin: Callable[[str, str], Response | None] = origin_get,
    delay: float = 0.5,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[Finding], dict[str, Any]]:
    u = urlparse(url)
    host = (u.hostname or "").lower()
    if u.scheme not in ("http", "https") or not host:
        raise ValueError("URL must look like https://example.com")
    if host != confirm_owner.strip().lower():
        raise ValueError(f"refusing to probe {host!r}: --confirm-owner must be exactly the host you own")
    try:
        ipaddress.ip_address(host)
        raise ValueError("use a domain name, not a bare IP")
    except ValueError as e:
        if "domain name" in str(e):
            raise
    out: list[Finding] = []
    info: dict[str, Any] = {"host": host, "requests": 0}
    base = f"https://{host}"

    def add(sev: str, title: str, loc: str = "", detail: str = "", rule: str = "") -> None:
        out.append(
            Finding("exposure", sev, title, loc or host, detail, rule or title.split(":")[0].lower().replace(" ", "-"))
        )

    def fetch(path: str, scheme: str = "https") -> Response | None:
        if info["requests"] >= MAX_REQUESTS:
            return None
        info["requests"] += 1
        r = get(f"{scheme}://{host}{path}")
        sleep(delay)
        return r

    ips = dns(host)
    cdn = cdn_for(ips)
    info.update(ips=ips, cdn=cdn)
    if cdn:
        add("info", f"Behind CDN: {cdn}", detail="Direct-to-origin access is checked only if you pass --origin-ip.")
    t = tls(host)
    info["tls"] = t
    if t.get("error"):
        add("high", "TLS: connection or certificate problem", detail=str(t["error"]), rule="tls-error")
    else:
        if str(t.get("version")) in ("TLSv1", "TLSv1.1", "SSLv3"):
            add("high", f"TLS: legacy protocol negotiated ({t['version']})", rule="tls-legacy")
        dl = t.get("days_left")
        if isinstance(dl, int) and dl < 30:
            add("high" if dl < 7 else "medium", f"TLS: certificate expires in {dl} day(s)", rule="tls-expiry")
    plain = fetch("/", "http")
    if plain and plain.status < 300 and not (plain.header("location") or "").startswith("https://"):
        add(
            "medium",
            "HTTP: site answers on port 80 without redirecting to HTTPS",
            f"http://{host}/",
            rule="no-https-redirect",
        )
    root = fetch("/")
    if root is None:
        add(
            "info", "Could not fetch the site over HTTPS", detail="Remaining header checks skipped.", rule="unreachable"
        )
        return out, info

    def h(name: str) -> str | None:
        return root.header(name)

    if not h("strict-transport-security"):
        add("medium", "Header: Strict-Transport-Security missing", rule="hsts-missing")
    if (h("x-content-type-options") or "").lower() != "nosniff":
        add("low", "Header: X-Content-Type-Options: nosniff missing", rule="nosniff-missing")
    if not h("x-frame-options") and "frame-ancestors" not in (h("content-security-policy") or ""):
        add(
            "low",
            "Header: clickjacking protection missing (X-Frame-Options / CSP frame-ancestors)",
            rule="clickjacking",
        )
    if not h("content-security-policy"):
        add("info", "Header: Content-Security-Policy not set", rule="csp-missing")
    for name in BANNER_HEADERS:
        val = h(name)
        if val and any(ch.isdigit() for ch in val):
            add(
                "medium" if name.startswith("x-asp") else "low",
                f"Banner: {name}: {val}",
                detail="Version disclosure helps attackers pick exploits.",
                rule="banner",
            )
    for c in root.all("set-cookie"):
        low = c.lower()
        nm = c.split("=", 1)[0]
        if "secure" not in low:
            add("low", f"Cookie {nm} lacks Secure", rule="cookie-secure")
        if "httponly" not in low:
            add("low", f"Cookie {nm} lacks HttpOnly", rule="cookie-httponly")
    junk = "/" + "".join(random.choices(string.ascii_lowercase, k=14)) + ".html"  # soft-404 baseline
    base404 = fetch(junk)
    soft = base404 is not None and base404.status == 200
    for p in DIR_PATHS:
        r = root if p == "/" else fetch(p)
        if r and r.status == 200 and any(m in r.body.decode("latin-1") for m in DIR_MARKERS):
            add("high", "Directory listing enabled", f"{base}{p}", rule="directory-listing")
    for p in SENSITIVE:
        r = fetch(p)
        if r and r.status == 200 and r.body and not (soft and base404 and abs(len(r.body) - len(base404.body)) < 64):
            add(
                "high",
                f"Sensitive file reachable: {p}",
                f"{base}{p}",
                f"HTTP 200, {len(r.body)}+ bytes",
                "sensitive-file",
            )
    for p in PANELS:
        r = fetch(p)
        if (
            r
            and r.status in (200, 401)
            and not (soft and base404 and r.status == 200 and abs(len(r.body) - len(base404.body)) < 64)
        ):
            add(
                "low",
                f"Admin/login panel reachable from the internet: {p}",
                f"{base}{p}",
                "Consider IP allow-listing, MFA and rate limiting.",
                "admin-panel",
            )
    if origin_ip and cdn:
        try:
            ipaddress.ip_address(origin_ip)
        except ValueError as e:
            raise ValueError(f"--origin-ip: {e}") from e
        info["requests"] += 1
        r = origin(origin_ip, host)
        if r and r.status < 500:
            add("high", "Origin server answers directly (CDN/WAF can be bypassed)", origin_ip,
                f"HTTP {r.status} from {origin_ip}:443 with Host {host}. Restrict the origin firewall to the CDN's published ranges.", "origin-direct")  # fmt: skip
        else:
            add("info", "Origin did not answer directly on 443 (good)", origin_ip, rule="origin-direct-ok")
    elif cdn:
        add(
            "info",
            "Origin-direct check skipped",
            detail="Pass --origin-ip YOUR_ORIGIN_IP to test whether the origin bypasses the CDN.",
            rule="origin-skipped",
        )
    info["checked_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    return out, info
