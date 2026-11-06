# Contributing to iisguard

Thanks for helping. iisguard is MIT-licensed and community-driven; most contributions are **detections** (rules) and
**verified vulnerability data**, which are plain data files and easy to review.

## Ground rules

1. **Defensive use only.** No exploit code, no working malware, no real credentials. Test fixtures use harmless marker
   strings (see `tests/webroot_fixture.py`): dangerous-looking constructs sit in comments or act on constants.
2. **Never invent security facts.** A CVE id, fixed version or IOC must be traceable to an official source
   (vendor advisory, CISA KEV, NVD, php.net, wordpress.org, MSRC). Put the URL in the data file. If a vendor has not
   published a fixed version, mark the entry `status: manual` and leave the version out.
3. **Prefer false negatives over false positives for anything that can block.** A rule that fires on normal traffic
   will lock real users out. Every rule needs a `no_match` test that proves what it must leave alone.
4. **Safety first.** Anything that changes a system is dry-run by default, backs up, and can be rolled back.

## Development setup

```
git clone https://github.com/qmmughal/iisguard && cd iisguard
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check src tests scripts && mypy && pytest -q
```

Python 3.11+. The runtime has **no third-party dependencies**; optional extras are `yaml`, `win`, `report`. Dev tools
(`pysigma`, `yara-x`) only validate exports in tests and are skipped if absent.

## Adding or changing a rule

Edit `src/iisguard/rules/rules.yaml` (see `docs/writing-rules.md`). Each rule needs `id`, `category`, `score`,
`severity`, `field`, `pattern`, and `tests` with at least one `match` and one `no_match` sample. Patterns must be
RE2-compatible (no lookaround or backreferences): use `exclude:` for allow-lists so Sigma and CrowdSec exports stay
valid. Then:

```
python scripts/build_rule_pack_index.py   # after bumping src/iisguard/rules/VERSION (YYYY.MM.DD-N)
pytest -q
```

## Adding a vulnerability

Edit `src/iisguard/audit/data/known_fixed_versions.yaml` with the CVE, product, per-branch fixed versions, `sources`
(URLs you actually read), and `status`. Add a fixture row to `tests/fixtures/inventory.json` and a test.

## Pull requests

Small, focused PRs with tests. Describe what you verified and where. CI must be green on Linux and Windows. By
contributing you agree your work is released under the MIT license. Please follow `CODE_OF_CONDUCT.md`.

## False positives and bugs

Use the issue templates. For a false positive, include the (redacted) log line or file excerpt and which rule fired.
