# Writing rules

Rules are data in `src/iisguard/rules/rules.yaml` (published as the `web-core` rule pack in `rule-packs/`). A rule
inspects one field of a parsed log event; the same file feeds the scanner and the Sigma, ModSecurity and CrowdSec exports.

```yaml
- id: wp-setup-config-probe            # unique, kebab-case
  category: wordpress                  # groups rules; see ATTACK map in export/sigma.py
  score: 50                            # 0-1000; an IP is blocked at block_score (default 100)
  severity: medium                     # info | low | medium | high | critical
  field: path                          # path | query | uri | ua | method | message | line
  methods: [POST]                      # optional: only for these HTTP methods
  pattern: '/wp-admin/setup-config\.php'
  exclude: '/wp-admin/setup-config\.php\?step=-1'   # optional: ignore a hit when this ALSO matches
  description: Mass probing of the WordPress installer
  cve: [CVE-2026-119977]               # only ids verified in an official source
  tests:
    match:
      - '/wp-admin/setup-config.php'
    no_match:
      - '/wp-admin/admin-ajax.php'
```

## Fields

| field | what it contains |
|---|---|
| `path` | URL path, percent-decoded (twice, to catch double encoding) |
| `query` | query string, decoded, `+` turned into a space |
| `uri` | path + `?` + query, decoded |
| `ua` | user agent |
| `method` | HTTP method (use `methods:` instead to filter) |
| `message` | error-log text (PHP / Apache error logs) |
| `line` | the raw log line (rarely needed) |

Matching is case-insensitive and uses Python `re.search`. For speed, user agents and paths are cached.

## Rules of thumb

- **Anchor** (`^`, `$`, a leading `/`) so you do not match substrings of unrelated URLs.
- **Write the `no_match` tests first.** Think of the most normal request that contains your keyword.
- **No lookaround or backreferences.** Sigma (pySigma), CrowdSec (RE2) and the YARA engines reject them. Use `exclude`.
- Prefer several moderate rules (30-60) over one that can block alone. Reserve 90+ for markers that essentially
  never occur in normal traffic (a known web-shell file name, an exploit marker).
- Use `category: php-crash` with `score: 0` for lines that only feed the burst detector (not blockable).

## Test and publish

```
pytest tests/test_core.py -k rule_own_tests      # runs every rule's match / no_match samples
echo 2026.11.08-1 > src/iisguard/rules/VERSION    # bump (YYYY.MM.DD-N) when rules change
python scripts/build_rule_pack_index.py           # refresh rule-packs/ and the SHA-256 index
pytest -q
```

`iisguard update-rules` installs a pack only if it is newer, the SHA-256 matches, **and every rule's own tests pass**.
A broken installed pack never disables detection: iisguard falls back to the bundled rules.

## File signatures (web-shell hunter)

File signatures live in `src/iisguard/webshell.py` (`SIGS`) with per-group weights (`php`, `asp`, `jsp`) and combos
(input reaching process start). They are also exported to YARA. Add a test with a **harmless** marker file in
`tests/webroot_fixture.py`: put the dangerous-looking construct inside a comment or make it act on a constant
string. Never commit working malware.

## Your own rules

Copy `rules.yaml`, edit it, and point iisguard at it: `"rules_path": "C:\\iisguard\\my-rules.yaml"` in the config, or
`--rules my-rules.yaml`. Disable single rules with `"disabled_rules"`.
