# Tuning false positives

iisguard is built to **report broadly and block narrowly**. Detections never block by themselves: an IP is blocked
only when its accumulated score reaches `block_score` (default 100) *and* it is not protected. Start in dry-run,
read the output for a week, then enable `--live`.

## How scoring works

Each rule adds its `score` the first time an IP triggers it; repeats add 20 % each, up to 5 repeats. A request that
succeeds (HTTP 2xx) on a high/critical rule counts 1.5x. Behaviours add their own scores: flood 80, 4xx scanning 60,
login brute force 100, distributed spray 70 per IP. So one probe (30-60 points) never blocks; a scanner that tries a
dozen things does; one clear compromise attempt (PHP upload-progress marker = 100) does.

## The safe levers, in order

1. **Allow-list** trusted addresses (monitoring, office, partners): `allowlist` in `iisguard.json`
   (`"allowlist": ["203.0.113.10", "198.51.100.0/24"]`) or `IISGUARD_ALLOWLIST=...`. Allow-listed IPs are never blocked
   but are still reported.
2. **Raise the block threshold** (`block_score`) or lower `max_blocks` while you gain confidence.
3. **Disable one rule** by id: `"disabled_rules": ["phpmyadmin-probe"]`.
4. **Tune a behaviour**: `flood_requests` / `flood_window`, `scan4xx_count`, `spray_min_ips`, `brute_attempts`,
   `login_paths` (add your own login URL so spraying against it is seen, remove paths that do not apply).
5. **Add an `exclude`** to a rule in your own rules file (see `writing-rules.md`) instead of deleting it.

Never allow-list a whole CDN by hand: the bundled Cloudflare ranges (refresh with `iisguard update-rules --cdn`)
and your own `cdn_ranges` are already protected. If you are behind a CDN or load balancer, make sure your web server
logs the **real client IP** (X-Forwarded-For / CF-Connecting-IP); otherwise every request appears to come from the CDN
and nothing can be blocked usefully.

## Common causes

| Symptom | Likely cause | Fix |
|---|---|---|
| `behav-flood` on a user behind NAT | an office or mobile carrier sharing one IP, page with many non-static requests | raise `flood_requests`, allow-list the office |
| `behav-scan-4xx` for a monitoring tool | uptime checker hitting missing pages | allow-list it; fix the dead URLs |
| `webshell-post-image` | an app that POSTs to a URL ending in `.png` (a dynamic image handler) | disable or `exclude` that path |
| `sqli-basic` on a search box | users searching "union select" or SQL tutorials on a docs site | raise the rule's threshold by lowering its score in your rules file |
| `scanner-user-agent` | your own vulnerability scanner or pentest | allow-list its IP |
| `sensitive-file-probe` on `appsettings.json` | your app really serves that path | `exclude` it |
| login brute-force from one IP | a user who forgot a password, or a script | raise `brute_attempts` |

## File hunter (`hunt`) false positives

Reasons are listed per file; a finding at score 40-69 is "worth a look", not "malware".

- **"script file inside an upload/media folder"**: any folder named `uploads`, `media`, `images`, `files`, `tmp`,
  `attachments`... counts. Legitimate `index.php` stubs ("Silence is golden") are ignored; real applications that keep
  code in such a folder (some CMS media managers) will show up. Review once, then run with `--min-score 70`.
- **"processes" or "asp-process-start"** alone scores 30 and is not reported: admin tools that start processes are normal.
- **Encoded blobs**: a long base64 data URI in a template scores 25 and is not reported on its own.
- **"modified recently"** only adds 10 points to files that already have another reason.

If a clean file is flagged, open a "False positive" issue with the file excerpt (redacted) and the reasons list.

## Process detection

Web servers legitimately run helper programs. `sendmail`, `msmtp`, `wkhtmltopdf` and `git` are ignored; classic CGI
under Apache (`httpd` -> `sh`) will trigger, so exclude CGI directories by disabling process checks on that host
or by reviewing the events once. Admin-run `php`/`dotnet` on the command line are never judged.

## Exposure checks

`exposure` reports an admin login page as `low` ("reachable from the internet"): that is a hardening hint (add IP
allow-listing or MFA), not a vulnerability. Soft-404 sites (200 for every path) are detected and do not produce
"sensitive file" findings.
