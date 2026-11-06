# Incident-response checklist for a suspected web-server compromise

Order matters: **isolate → collect → quarantine → rotate secrets / machineKey → patch → monitor.** iisguard helps with
each step but never deletes evidence: it moves, backs up, and reports.

## 0. Decide quickly

You probably have an incident if `hunt` finds a critical file, a web worker spawned a shell (`hunt --events`), `scan`
shows `php2shell-upload-progress` hits that returned 200, or CISA/vendor advisories list a flaw you were exposed to
(`iisguard audit --kev`). For a KEV entry marked "forensic triage", assume possible compromise before the patch date.

## 1. Isolate

- Take the site out of rotation or block inbound traffic at the network edge. Do **not** reboot or wipe yet: memory
  holds evidence (in-memory implants such as Godzilla/BLUEBEAM inside `w3wp.exe` leave no file).
- Keep your own admin access working. If you use `iisguard block`, your admin session IP is protected automatically.
- Note the time. Everything before it is suspect.

## 2. Collect (read-only)

```
iisguard hunt <webroot> --since 14 --output-format json > hunt.json
iisguard scan <logs...> --output-format json > scan.json
iisguard audit --kev --output-format json > audit.json
iisguard fim check <webroot> --baseline <off-server copy>          # what changed since the baseline
iisguard hunt --checks "" --events security-4688.xml               # process events you exported
iisguard report hunt.json scan.json audit.json --format html --out incident.html
```

Also copy: IIS/nginx/Apache and PHP logs, `web.config`/`php.ini`, the application pool identity list, a memory dump of
the worker process if your policy allows, and the Windows Security (4688) / Sysmon (1) logs. Hash everything and
store copies off the server. Record the `sha256` values `hunt` prints.

## 3. Quarantine

```
iisguard quarantine <file>                 # dry-run: shows hash and size
iisguard quarantine <file> --apply         # moves it out of the web tree, keeps metadata
iisguard quarantine --list
```

Quarantine only after the file has been collected. Restore with `--restore ID` if it turns out to be legitimate.
Check for persistence the file hunter cannot see: scheduled tasks, services, new local admins, new IIS modules/handlers
(`appcmd list modules`), startup folders, `.user.ini` and `auto_prepend_file`.

## 4. Rotate secrets and the machineKey

Assume everything the web process could read is exposed: database passwords, API keys in `.env` / `appsettings*.json`
/ `wp-config.php`, cloud credentials, SMTP passwords, `machineKey` values.

```
iisguard hunt <webroot> --checks secrets,webconfig      # find what was readable (values are masked)
iisguard fix machinekey <webroot>                       # dry-run, masked diff
iisguard fix machinekey <webroot> --apply               # unique random keys per site, backup made first
```

Rotating the machineKey signs everyone out and invalidates ViewState. In a **web farm** every node needs the same new
key. Rotate keys at the provider (OpenAI, Anthropic, AWS, Stripe...) and revoke the old ones; do not just edit the file.
Reset admin passwords and sessions for the CMS and any account that logged in during the window.

## 5. Patch

- Run `iisguard audit --kev` and fix every `vulnerable`/`eol` row; install OS updates (HTTP.sys/IIS), .NET runtimes,
  PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later), WordPress (7.1.4 or your branch's fix), SharePoint/Exchange updates.
- Temporary mitigations if you cannot patch at once: `iisguard fix php-ini --apply`, `fix wp-upgrade-dir --apply`,
  `fix uploads <dirs> --apply`. They are not substitutes for the patch.
- Rebuild from a known-good source where you can; do not trust a cleaned host you cannot fully explain.

## 6. Monitor

```
iisguard fim init <webroot> --baseline fim.json      # new baseline AFTER cleanup; store it off-server
iisguard watch <logs...> --backend auto              # dry-run first, then --live
```

Re-run `hunt` daily for two weeks. Export your IOCs for other tools: `iisguard export sigma|yara|crowdsec|modsec`.

## 7. Tell people

Check your legal and contractual notification duties (customers, regulators, your cyber insurer). Write a short
timeline while it is fresh: first indicator, containment time, what was accessed, what was rotated, what was patched.
