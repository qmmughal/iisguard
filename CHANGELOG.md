# Changelog

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
