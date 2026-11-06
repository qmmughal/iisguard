# Security policy

## Reporting a vulnerability in iisguard

Please **do not open a public issue** for a security problem in iisguard itself (for example a way to make it block
the wrong address, write outside the files it was pointed at, leak a secret into output, or execute a command).

Report it privately through GitHub: **Security tab → "Report a vulnerability"** on
<https://github.com/qmmughal/iisguard>. Include the version (`iisguard --version`), your OS, and steps to
reproduce. You can expect an acknowledgement within a few days; fixes ship as a patch release with credit
(unless you prefer to stay anonymous).

## What is in scope

- The safety guarantees: protected addresses (admin session, own IPs, private ranges, allowlist, CDN ranges) must never
  be blocked; dry-run must not change anything; `--apply` must back up first; rollback must restore.
- Output that should be masked (secret values, machineKeys) appearing in clear text.
- Path handling bugs (symlink following, writing outside the target), command or XML injection, unsafe downloads in
  `update-rules`, and the `--confirm-owner` guard of the HTTP checks.

## What is out of scope

- A web-shell, exploit or scan technique that iisguard does not detect. That is a *detection gap*: open a normal issue
  with the "new rule" template, using harmless marker strings, never working malware or exploit code.
- Vulnerabilities in the software iisguard audits (PHP, WordPress, IIS...). Report those to their vendors.

## Supported versions

Only the latest release receives fixes while the project is pre-1.0.

## Trust model and known limits

- Rule packs fetched by `update-rules` are checked against a SHA-256 from the index served by the same repository.
  That detects corruption, not a compromised publisher. Pin your own rules with `rules_path` if you need that.
- The FIM baseline is only as trustworthy as where you store it: keep a copy off the web server.
- iisguard is a detection and hardening aid. It does not replace patching, backups, or an EDR.
