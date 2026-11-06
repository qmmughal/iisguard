"""Deny web access to WordPress upgrade staging and the installer script.

The rule goes into the SITE-LEVEL web.config (requestFiltering denyUrlSequences), not into wp-content/upgrade itself,
because WordPress empties that folder after upgrades and would delete a web.config placed there.
CVE-2026-119977's exact staging path is not confirmed by any source we read: this is defence in depth. The fix is 7.1.4+.
"""

from __future__ import annotations

from pathlib import Path

from iisguard.fix.base import Change, FixPlan, read_text
from iisguard.fix.xmledit import has, insert, new_config, validate

SEQUENCES = ["/wp-content/upgrade/", "/wp-admin/setup-config.php"]

NGINX = """location ^~ /wp-content/upgrade/ { deny all; return 404; }
location = /wp-admin/setup-config.php { deny all; return 404; }"""
HTACCESS = """# add to the site root .htaccess (Apache 2.4)
RedirectMatch 404 ^/wp-content/upgrade/
<Files "setup-config.php">
  Require all denied
</Files>"""


def plan(wp_root: str) -> FixPlan:
    root = Path(wp_root)
    fp = FixPlan("wp-upgrade-dir", snippets={"nginx": NGINX, "apache": HTACCESS})
    if not (root / "wp-includes" / "version.php").exists():
        fp.notes.append(f"{root} does not look like a WordPress root (wp-includes/version.php missing).")
        return fp
    p = root / "web.config"
    old = read_text(p) if p.exists() else None
    text = old or ""
    added: list[str] = []
    for seq in SEQUENCES:
        if has(text, rf'sequence\s*=\s*"{seq}"'):
            continue
        frag = f'<add sequence="{seq}" />'
        if text:
            text = insert(text, ["system.webServer", "security", "requestFiltering", "denyUrlSequences"], frag)
        else:
            text = new_config(
                "  <system.webServer>\n    <security>\n      <requestFiltering>\n        <denyUrlSequences>\n"
                f"          {frag}\n        </denyUrlSequences>\n      </requestFiltering>\n    </security>\n  </system.webServer>\n"
            )
        added.append(seq)
    if added:
        validate(text)
        fp.changes.append(Change(p, text, "deny URL sequences: " + ", ".join(added), old))
    else:
        fp.notes.append("The deny rules already exist.")
    upg = root / "wp-content" / "upgrade"
    if upg.is_dir() and any(upg.iterdir()):
        fp.notes.append(
            f"{upg} contains leftovers ({sum(1 for _ in upg.iterdir())} entries). Review and delete them by hand after backup."
        )
    fp.notes += [
        "Blocking /wp-admin/setup-config.php is safe on an installed site (it is only needed for first-time setup).",
        "Update WordPress to 7.1.4 or the fixed release of your branch: this rule is not a substitute for the patch.",
    ]
    return fp
