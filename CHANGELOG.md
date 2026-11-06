# Changelog

## 0.4.0 (unreleased) - M4 + M5: block, fix, export, report, exposure, release
- Firewall: `netsh`, `nftables` (single atomic transaction), `iptables` (new chain + `iptables-restore`, then swap),
  optional Cloudflare IP Access Rules (token from the environment). Add-then-remove sync, undo on failure, cap with
  lowest-score eviction, TTL expiry, `block list|sync|unban|rollback|clear`. Every IP passes the protector again at
  sync time, including IPs read back from the state file.
- `watch`: poll-based tailer (truncation/rotation safe, keeps the IIS `#Fields:` header), rolling score window.
- Fixes with masked diff, backup, `--apply`, `fix rollback`: `machinekey`, `headers`, `uploads`, `php-ini`,
  `wp-upgrade-dir`; `quarantine` (+ `--restore`). Text-level web.config editing keeps comments, BOM and CRLF.
- `service`: Task Scheduler XML / systemd unit generation (dry-run unless `--apply`).
- Exports: Sigma (validated with pySigma), YARA (validated with yara-x), CrowdSec scenarios + blocklist (RE2-safe),
  ModSecurity/Coraza `SecRule`s (detect | block | crs modes), IP lists (txt/csv/json/nft).
- Reports: CSV (formula-injection safe), JSON, single-file offline HTML (dark/light, escaped, CSP), SARIF 2.1.0.
- `exposure --url`: headers, TLS, HTTP->HTTPS, banners, cookies, directory listing, sensitive files, admin panels,
  origin-direct check with a user-supplied origin IP. Refuses any host not confirmed with `--confirm-owner`.
- `update-rules [--cdn]`: SHA-256 + per-rule tests before install, previous copy kept, falls back to bundled rules.
  New `exclude` rule field replaces lookahead so every rule exports cleanly to RE2-based tools.
- Docs, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, issue templates, release workflow (PyPI trusted publishing + zipped
  Windows bundle with SHA-256), single-file `.pyz` bundle.
- Bug fixed during testing: netsh batch rule names were derived from the IP index, so every batch got the same name.

## 0.3.0 (unreleased) - M3: hunt, FIM, process detection
- `iisguard hunt PATH... [--checks files,secrets,webconfig,processes] [--since DAYS] [--events FILE]`.
- File hunter (`webshell.py`): PHP / ASPX / JSP signatures, decode-chain and request-to-exec combos, entropy / long
  encoded blobs, masquerading files (script code inside images/text, double extensions), scripts in upload folders,
  `.user.ini` / `.htaccess` `auto_prepend_file`, handler mappings that run images as scripts, unexpected `.aspx`
  under `/owa/auth/`, recent `.aspx` under SharePoint `_layouts`. Location rules use the path relative to the scan root.
- `fim init|check`: SHA-256 baseline of scripts/config/js, reports added / modified / deleted, flags new scripts in uploads.
- Process detection (`process.py`): web worker (w3wp, php-cgi, php-fpm, httpd, nginx, tomcat...) spawning shells or recon
  tools. Inputs: exported Security 4688 / Sysmon 1 XML, auditd, live process list (`ps` / read-only CIM query).
- `audit/secrets.py`: `.env`, `appsettings*.json`, wp-config backups, `.git`, key files, OpenAI / Anthropic / AWS / Stripe /
  GitHub / Slack patterns. Values are always masked. Optional reachability check (`--url` + `--confirm-owner`) is
  rate-limited, capped at 50 URLs, never follows redirects and refuses any host you did not confirm.
- `audit/webconfig.py`: hard-coded and shared machineKeys (fingerprints only), `enableViewStateMac=false`, debug, tracing,
  customErrors, directory browsing, missing request limits. DOCTYPE/ENTITY files are refused.
- Fixes found while testing: location rules were evaluated on absolute paths (a scan under a `Temp` folder flagged
  everything); `php-fpm: pool www` process titles never matched.

## 0.2.0 (unreleased) - M2: KEV audit
- `iisguard audit [--kev] [--offline] [--inventory FILE] [--webroot D] [--app-root D] [--php-dir D]`.
- CISA KEV loader: live download, 24 h cache, stale-cache fallback, bundled web-facing snapshot (catalog 2026.11.06).
- `known_fixed_versions.yaml`: every entry cites its sources and a status (verified / partial / manual).
  Fixed versions verified against php.net, wordpress.org, NVD/MSRC. Unpublished data is never guessed.
- Collectors (read-only): PHP binaries + `session.upload_progress`, `dotnet --list-runtimes`, self-contained
  .NET apps (`*.deps.json`), WordPress `version.php` + leftover `wp-content/upgrade`, Windows build + UBR, IIS,
  SharePoint, Exchange.
- Corrections to the project brief, found while verifying: CVE-2026-70247 (HTTP.sys) is a local out-of-bounds read per
  NVD, not remote RCE; CVE-2026-96230 is XSS per NVD, not RCE; CVE-2026-115560 is real (php.net 2026-10-23) but
  unpatched and absent from NVD; the WordPress staging path is unconfirmed.

## 0.1.0 (unreleased) - M1: core + log analysis
- Streaming parsers: IIS W3C, nginx/Apache combined, PHP/Apache error logs, JSON lines, auto-detect.
- Rule pack (`rules/rules.yaml`, version file `rules/VERSION`) with per-rule tests; core is stdlib-only.
- Analyzer: scoring, sliding windows (flood, 4xx scanning, login brute force), distributed password-spray
  detection, /24 and /48 aggregation, PHP crash bursts.
- Safety layer: admin RDP/SSH IP auto-detect, server's own IPs, private ranges, allowlist, CDN ranges.
- `iisguard scan` (dry-run); all other commands are listed in `--help` and report their milestone.
