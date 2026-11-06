# Changelog

## 0.1.0 (unreleased) - M1: core + log analysis
- Streaming parsers: IIS W3C, nginx/Apache combined, PHP/Apache error logs, JSON lines, auto-detect.
- Rule pack (`rules/rules.yaml`, version file `rules/VERSION`) with per-rule tests; core is stdlib-only.
- Analyzer: scoring, sliding windows (flood, 4xx scanning, login brute force), distributed password-spray
  detection, /24 and /48 aggregation, PHP crash bursts.
- Safety layer: admin RDP/SSH IP auto-detect, server's own IPs, private ranges, allowlist, CDN ranges.
- `iisguard scan` (dry-run); all other commands are listed in `--help` and report their milestone.
