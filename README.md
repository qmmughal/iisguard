# iisguard

Free, MIT-licensed website-defense toolkit for IIS, nginx, Apache and PHP hosts. Standard-library-only core, Python 3.11+.

> **Status: early development (M3 of 5).** Log analysis (`scan`), software audit (`audit`), web-shell / secrets /
> web.config hunting (`hunt`) and file-integrity monitoring (`fim`) work. The other commands are listed in
> `iisguard --help` and are being built; each prints the milestone it is planned for.

Goals: **audit** exposure to actively exploited web vulnerabilities, **detect** attacks in logs/files/processes,
**block** attackers at the host firewall (safely), **fix** with reversible guided remediation, and **share**
detections as Sigma, YARA, CrowdSec and ModSecurity rules.

## Quick start

```text
pip install .
iisguard scan C:\inetpub\logs\LogFiles\W3SVC1\u_ex261107.log
iisguard scan /var/log/nginx/access.log /var/log/php8.3-fpm.log --output-format json
```

`scan` is read-only. It reports what it **would** block; nothing touches your firewall.

## Audit exposure (CISA KEV + known fixed versions)

```
iisguard audit --kev                       # this machine; downloads the CISA KEV feed (cached 24 h)
iisguard audit --kev --offline             # no network: cache or bundled snapshot
iisguard audit --webroot D:\sites --app-root D:\apps --php-dir C:\php
iisguard audit --inventory inventory.json  # audit a JSON inventory (see tests/fixtures/inventory.json)
```

Output: status, CVE, product, found version, fixed version, KEV due date, action. Statuses: `vulnerable`, `eol`,
`config` (needs a setting changed), `verify` (cannot be decided automatically, e.g. distro-patched PHP), `manual`
(vendor has not published version data; we do not guess). Collectors only read: they run `php -v`/`php -i`,
`dotnet --list-runtimes` and read files/registry.

## Hunt for compromise

```
iisguard hunt D:\sites                                   # web-shells, exposed secrets, risky web.config
iisguard hunt D:\sites --since 14                        # also weigh files changed in the last 14 days
iisguard hunt D:\sites --checks secrets --url https://example.com --confirm-owner example.com
iisguard hunt --checks "" --events security-4688.xml     # w3wp/php spawning shells, from exported events
iisguard fim init D:\sites --baseline fim.json           # keep a copy of fim.json off the server
iisguard fim check D:\sites --baseline fim.json --fail-on-change
```

Everything is read-only. Secret values are masked (first 4 characters and the length). The `--url` reachability check
only runs for the host you pass to `--confirm-owner`, at 2 requests per second, at most 50 URLs.

Known limits: signatures are text-based (a webshell with no known pattern and low entropy will be missed);
in-memory implants that never start a process cannot be seen by file or process checks (use EDR / memory forensics);
folders named `files`, `media`, `tmp` or `images` are treated as upload folders, so legitimate scripts there need
review. Process checks need Security event 4688 command-line auditing or Sysmon to be enabled.

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
