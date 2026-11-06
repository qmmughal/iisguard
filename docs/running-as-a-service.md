# Running iisguard as a service

`iisguard watch` tails your logs, scores attackers and keeps the firewall block list in sync. Run it unattended as
a service. **Start in dry-run for at least a week**: the service logs what it would block without touching the
firewall. Add `--live` only when the output looks right.

## Before you start

1. `iisguard scan <yesterday's log>`: read the "Would block" and "Protected" sections.
2. Create `iisguard.json` (see `iisguard.example.json`): add your office/monitoring IPs to `allowlist` and, if you
   use a CDN or load balancer, make sure the log shows the **real client IP**.
3. Run `iisguard block sync <log> --admin-ip <your-ip>` (dry-run) and read the command list.

iisguard never blocks: your current RDP/SSH session IP (detected from `netstat`/`ss` and `SSH_CONNECTION`), the
server's own IPs, private/loopback addresses, allow-listed IPs, or CDN/load-balancer ranges. Pass `--admin-ip` for
any other address you administer from.

## Generate the service definition (nothing is installed)

```
iisguard service install --logs C:\inetpub\logs\LogFiles\W3SVC1\u_ex.log --backend netsh
iisguard service install --logs /var/log/nginx/access.log --backend nftables --write-dir ./svc
```

This prints the Task Scheduler XML (Windows) or systemd unit (Linux) and the commands that would run. Add
`--live` to make the *installed service* enforce, and `--apply` to actually install it (run as Administrator/root).
`--write-dir` writes the files so you can review and install them yourself.

### Windows (Task Scheduler, no extra dependency)

`--apply` registers a task named `iisguard` that starts at boot as SYSTEM and restarts on failure:
`schtasks /Create /TN iisguard /XML iisguard-task.xml /F`. Start/stop: `iisguard service start|stop --apply`
(`schtasks /Run|/End`). Remove: `iisguard service uninstall --apply`.

IIS rotates logs daily into a new file name (`u_exYYMMDD.log`). Point `--logs` at the **current** file, or restart the
task from a daily trigger; wildcard following is on the roadmap. Prefer NSSM or a pywin32 service if you need a real
Windows service: wrap `python -m iisguard watch ...` the same way.

### Linux (systemd)

`--apply` writes `/etc/systemd/system/iisguard.service`, runs `systemctl daemon-reload` and `systemctl enable iisguard`.
Then `iisguard service start --apply` (or `systemctl start iisguard`). Logs: `journalctl -u iisguard`.

## Block list management

```
iisguard block list                 # what is blocked now, with expiry
iisguard block unban 45.9.1.10 --live
iisguard block rollback --live       # restore the previous generation
iisguard block clear --live          # remove every iisguard firewall rule
```

Blocks expire after `--ttl` (default 24 h). Each sync adds the new generation first and removes the old one only
after the add succeeded; if the add fails, the previous rules stay in place. The list is capped by `max_blocks`
(lowest scores are dropped first). State lives in `%PROGRAMDATA%\iisguard` or `~/.local/state/iisguard`
(override with `IISGUARD_STATE_DIR`).

## Backends

| Backend | Mechanism | Notes |
|---|---|---|
| `netsh` | Windows Firewall rules `iisguard-<gen>-<n>`, 200 IPs each | needs Administrator |
| `nftables` | one `nft -f -` transaction replacing a set in table `inet iisguard` | atomic; needs root |
| `iptables` | new chain per generation, filled with `iptables-restore`, then swapped in | v4 and v6; needs root |
| `cloudflare` | zone IP Access Rules via the API | `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID` in the environment, never in a file; not exercised against a live account by the author |

## Safety checklist

- [ ] Dry-run output reviewed for a week
- [ ] `allowlist` contains monitoring, office, partner and payment-provider webhook IPs
- [ ] Real client IP appears in the logs (CDN / proxy headers)
- [ ] A second admin path exists (console/out-of-band) in case a rule is wrong
- [ ] You know how to undo: `iisguard block clear --live`
