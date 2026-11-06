# iisguard

[![CI](https://github.com/qmmughal/iisguard/actions/workflows/ci.yml/badge.svg)](https://github.com/qmmughal/iisguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A free, MIT-licensed **website-defense toolkit** for IIS, nginx, Apache and PHP hosts. Python 3.11+, standard-library-only core.

| | |
|---|---|
| **Audit** | Finds exposure to actively exploited vulnerabilities (CISA KEV + a maintained fixed-version map) |
| **Detect** | Attacks in logs, web-shells in files, shells spawned by web workers, risky config, exposed secrets |
| **Block** | Scores attackers and blocks them at the host firewall, with hard safety rails |
| **Fix** | Guided, reversible remediation: dry-run diff, backup, `--apply`, rollback |
| **Share** | Exports detections as Sigma, YARA, CrowdSec and ModSecurity/CRS rules |

> **Status: 0.x, pre-1.0.** Read the [limits](#limits) before relying on it in production. Everything is **read-only /
> dry-run by default**: changes need `--apply` (files) or `--live` (firewall), and nothing is sent anywhere
> (no telemetry; network only for the CISA feed, `update-rules`, and exposure checks you explicitly run).

## Install

```
pip install .                 # from a clone; after the first PyPI release: pip install iisguard
iisguard --help
```

Windows without Python tooling: download `iisguard-windows-bundle.zip` from the Releases page (single-file `.pyz` +
launcher; needs Python 3.11+). Optional extras: `.[yaml]`, `.[win]` (pywin32), `.[report]`.

## Threat → detection → fix

CVE data below was checked against CISA KEV, NVD, php.net and wordpress.org on 2026-11-07. Where a vendor has not
published a fixed version, iisguard says so instead of guessing.

| Threat | How iisguard detects it | Fix |
|---|---|---|
| **PHP "php2shell"** CVE-2026-109618 / -109619 (KEV, unauthenticated RCE) | `audit` (PHP versions, EOL branches), log rule on `PHP_SESSION_UPLOAD_PROGRESS`, PHP fatal/crash bursts, `hunt` for dropped shells, web worker → shell (`hunt --events`) | Update to **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** or later; temporary `fix php-ini` |
| **PHP CVE-2026-115560** (session upload progress; no patch yet) | `audit` reports `config` when `session.upload_progress.enabled` is on | `fix php-ini` sets it to 0 (php.ini / FPM pool, not `.user.ini`) until the next PHP release |
| **WordPress core CVE-2026-119977** (KEV, upgrade-window TOCTOU RCE) | `audit` (version, leftover `wp-content/upgrade`), log rules for `setup-config.php` and upgrade-folder probes | Update to **7.1.4** (or your branch's fix); `fix wp-upgrade-dir` (defence in depth) |
| **ASP.NET Core** CVE-2026-69304 (decompression DoS) and the Oct-2026 fixes | `audit`: `dotnet --list-runtimes`, self-contained apps via `*.deps.json` | Runtime **8.0.31 / 9.0.20 / 10.0.12** or later; request-limit advice from the web.config audit |
| **Windows HTTP.sys / IIS** CVE-2026-70247, -78459 (local per NVD) | `audit` compares the OS build with NVD's fixed builds | October 2026 cumulative update |
| **SharePoint** CVE-2026-102866, **Exchange** CVE-2026-70571 | `audit` (SE build compared; Exchange: manual), log rules for `ToolPane`/`spinstall`/`/owa/auth/*.aspx`, `hunt` for new `.aspx` | Vendor security updates (MSRC) |
| **Web-shells** (ASPX/PHP/JSP, disguised images, `.user.ini` prepend) | `hunt` (signatures, entropy, location), `fim check`, YARA export | `quarantine`, rotate secrets, patch |
| **ViewState / machineKey abuse** | log rule for oversized GET `__VIEWSTATE`; web.config audit finds hard-coded and **shared** keys | `fix machinekey` (unique random keys, masked diff) |
| **Password spraying, credential stuffing, scanning** | distributed-spray detector (many IPs × few attempts), brute force, floods, 4xx bursts, /24 and /48 grouping, scanner fingerprints | `block` / `watch --live` |
| **Exposed secrets** (`.env`, `appsettings*.json`, wp-config backups, `.git`, OpenAI/Anthropic/AWS/Stripe keys) | `hunt` (always masked); optional HTTP reachability check | rotate keys; deny serving the files |
| **Weak external posture** (headers, TLS, listings, admin panels, origin behind CDN) | `exposure --url` (only for hosts you confirm you own) | `fix headers`, `fix uploads` |

## 5-minute quickstart: IIS

```powershell
pip install .
iisguard audit --kev                                  # what is vulnerable on this server?
iisguard scan C:\inetpub\logs\LogFiles\W3SVC1\u_ex261107.log   # attacks in yesterday's log
iisguard hunt C:\inetpub\wwwroot --since 14           # web-shells, secrets, risky web.config
iisguard fim init C:\inetpub\wwwroot --baseline fim.json       # keep a copy off the server
iisguard block sync C:\inetpub\logs\LogFiles\W3SVC1\u_ex261107.log    # DRY-RUN: shows the netsh commands
iisguard fix headers C:\inetpub\wwwroot               # dry-run diff of web.config; add --apply to write (backup first)
```

Enable *Process Creation* auditing with command line (event 4688) or Sysmon to use the process check. Then run
`iisguard service install --logs <current log>` (dry-run) and see [docs/running-as-a-service.md](docs/running-as-a-service.md).

## 5-minute quickstart: nginx / Apache

```bash
pip install .
sudo iisguard audit --kev --webroot /var/www --php-dir /usr/sbin
iisguard scan /var/log/nginx/access.log /var/log/php8.3-fpm.log --output-format json > scan.json
iisguard hunt /var/www/html --since 14
iisguard export modsec --mode detect --out iisguard.conf      # add to ModSecurity/Coraza next to OWASP CRS
iisguard export crowdsec --out ./crowdsec --from scan.json    # scenarios + blocklist
iisguard block sync /var/log/nginx/access.log --backend nftables   # DRY-RUN: shows the nft transaction
```

Behind Cloudflare, CloudFront or a load balancer? Log the real client IP, or blocking is pointless (and CDN ranges are
protected from blocking). Refresh the CDN lists with `iisguard update-rules --cdn`.

## Commands

| Command | What it does |
|---|---|
| `scan LOG...` | analyze IIS / nginx / Apache / PHP-error / JSON logs (streaming, `.gz` ok); never changes anything |
| `watch LOG...` | tail logs and keep the block list in sync (`--live` to enforce) |
| `audit [--kev] [--offline]` | inventory + KEV + fixed versions → table of CVE, product, found, fixed, KEV due date, action |
| `hunt PATH...` | web-shells, secrets (masked), web.config, processes (`--events`) |
| `fim init\|check` | file-integrity baseline of the webroot |
| `block list\|sync\|unban\|rollback\|clear` | firewall block list; add-then-remove atomic sync |
| `fix machinekey\|headers\|uploads\|php-ini\|wp-upgrade-dir [--apply]`, `fix rollback` | reversible remediation |
| `quarantine FILE [--apply]` | move a suspicious file out of the web tree; `--restore ID` |
| `exposure --url U --confirm-owner HOST` | read-only external check, rate-limited |
| `export sigma\|yara\|crowdsec\|modsec\|iplist` | share detections |
| `report JSON... --format csv\|json\|html\|sarif` | single-file offline HTML (dark/light), SARIF 2.1.0 |
| `service install\|uninstall\|start\|stop` | Task Scheduler / systemd (dry-run unless `--apply`) |
| `update-rules [--cdn]` | newer rule pack (validated before install) and CDN ranges |

## Safety rules (non-negotiable)

- Dry-run by default. `--apply` for fixes, `--live` for the firewall. Fixes back up first and support rollback.
- **Never blocked:** allow-listed IPs, your current RDP/SSH session IP (auto-detected), the server's own IPs, private
  and loopback ranges, configured/bundled CDN and load-balancer ranges. One choke point (`firewall/safety.py`) is used
  by every backend and re-checked at sync time, even for IPs already in the state file.
- Firewall sync is atomic: the new generation is added first and the old one removed only after success; the list is
  capped and the lowest scores are evicted first. Commands run without a shell; every IP is validated first.
- Secrets and machineKeys are masked in all output. External HTTP checks refuse any host you did not confirm.
- Test fixtures use harmless marker strings, never working malware or exploit code.

## How it compares

iisguard is a **host-side audit/detect/respond toolkit**, not an inline WAF. It complements these projects:

| Tool | What it is | How iisguard relates |
|---|---|---|
| **IPBan** | Free brute-force IP blocker driven by event logs (Windows focus) | IPBan is excellent for login failures; iisguard adds web-log attack detection, KEV audit, file hunting and fixes. Use both. |
| **CrowdSec** | Detection engine + community blocklist/bouncers | iisguard exports CrowdSec scenarios and blocklists; CrowdSec's shared community intelligence is something iisguard does not have. |
| **ModSecurity / Coraza + OWASP CRS** | Inline WAF that can block a request before the app sees it | The right place to block exploit payloads. iisguard emits ModSecurity rules (`export modsec`) and covers what a WAF cannot: patch audit, file integrity, post-compromise hunting. |
| **LOKI / YARA** | IOC and YARA file/process scanner | iisguard's hunter is narrower (web roots) but understands IIS/PHP context; `export yara` gives you its signatures for YARA-based scanners. |
| **Wordfence** | WordPress-only firewall + malware scanner | Wordfence knows WordPress internals deeply. iisguard covers the whole server (IIS, PHP, .NET, SharePoint, Exchange) and is not WordPress-specific. |

## Limits

Read these before you trust the output.

- **Not a WAF and not an EDR.** It sees logs, files and process events after the fact. It cannot stop an unauthenticated
  RCE in progress: patch, and keep a WAF in front.
- **In-memory web-shells** (Godzilla/BLUEBEAM inside `w3wp.exe`) leave no file; process checks only catch child
  processes. Use EDR / memory forensics. Web-shell signatures are text-based and can be evaded by novel obfuscation.
- **POST bodies are not in access logs.** Multipart/chunked upload attacks are visible only through markers in the URI
  or through a WAF; the ModSecurity export adds a body-level rule for `PHP_SESSION_UPLOAD_PROGRESS`.
- **Version audit limits:** distro-patched PHP (Ubuntu/Debian/RHEL) shows `verify` because fixes are backported
  without changing the version; the `session.upload_progress` value is read from the CLI's php.ini and FPM pools can
  override it; Exchange and non-SE SharePoint have no published fixed build in NVD, so they are reported as `manual`.
- **Data corrections we found** are recorded in the changelog: CVE-2026-70247 (HTTP.sys) is a local issue per NVD,
  CVE-2026-96230 is XSS per NVD, and the exact WordPress staging path of CVE-2026-119977 is unconfirmed, so the
  upgrade-folder rule is a heuristic.
- **Behind a CDN you need the real client IP in the logs**, otherwise nothing can be blocked usefully.
- **Rule updates** are integrity-checked (SHA-256, per-rule tests) but not signed; see [SECURITY.md](SECURITY.md).
- **Not yet exercised on live systems by the author:** real `netsh` / `nft` / `iptables` runs, Cloudflare API calls,
  Task Scheduler / systemd installation, CrowdSec loading. They are covered by unit tests with fake runners and print
  the exact commands in dry-run so you can review them first.
- Azure Front Door ranges are not bundled (no stable URL); add them to `cdn_ranges`.

## Documentation

[False-positive tuning](docs/false-positives.md) · [Writing rules](docs/writing-rules.md) ·
[Running as a service](docs/running-as-a-service.md) · [Incident-response checklist](docs/incident-response.md) ·
[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

Rule packs are versioned separately (`rule-packs/`) and pulled with `iisguard update-rules`, so detections can be
contributed and shipped without a new release.

## License

MIT. Use it, fork it, ship it.
