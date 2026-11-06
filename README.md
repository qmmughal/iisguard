# iisguard

Free, MIT-licensed website-defense toolkit for IIS, nginx, Apache and PHP hosts. Standard-library-only core, Python 3.11+.

> **Status: early development (M1 of 5).** Log analysis (`scan`) works. The other commands are listed in
> `iisguard --help` and are being built; each prints the milestone it is planned for.

Goals: **audit** exposure to actively exploited web vulnerabilities, **detect** attacks in logs/files/processes,
**block** attackers at the host firewall (safely), **fix** with reversible guided remediation, and **share**
detections as Sigma, YARA, CrowdSec and ModSecurity rules.

## Quick start

```text
pip install .
iisguard scan C:\inetpub\logs\LogFiles\W3SVC1\u_ex261107.log
iisguard scan /var/log/nginx/access.log /var/log/php8.3-fpm.log --output-format json
```text

`scan` is read-only. It reports what it **would** block; nothing touches your firewall.

## Safety principles

- Read-only and dry-run by default. Changes will require `--apply` (fixes) or `--live` (firewall), with backup and rollback.
- Never blocks: allowlisted IPs, your current RDP/SSH session IP (auto-detected), the server's own IPs,
  private ranges, or CDN/load-balancer ranges.
- No telemetry. Network access only for opt-in features (KEV feed, rule updates, exposure checks).
- Test fixtures use harmless marker strings, never working exploits.

## Current detections (rule pack `rules/rules.yaml`)

PHP2Shell upload-progress probes, WordPress `setup-config.php` / `wp-content/upgrade/` probes, oversized GET
`__VIEWSTATE`, web-shell patterns (POST to images, `UpdateChecker.aspx`, double extensions, PHP in uploads),
SharePoint and Exchange path IOCs, secret/config probes, scanner user agents, SQLi/traversal fragments, plus
behavioural detection: floods, 4xx scanning bursts, login brute force, distributed password spraying (with /24
and /48 aggregation) and PHP crash bursts.

CVE identifiers in rules are verified against official advisories before being added; unverified ones are not tagged.

## Contributing

Rules are data: add a rule with `match` and `no_match` test strings to `src/iisguard/rules/rules.yaml` and run
`pytest`. Issues and pull requests welcome. See `CHANGELOG.md`.

## License

MIT. Use it, fork it, ship it.
