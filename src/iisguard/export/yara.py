"""YARA rules generated from the web-shell signatures, plus config / polyglot rules."""

from __future__ import annotations

import re

from iisguard.export import re2_compatible
from iisguard.webshell import SIGS, Sig

TAGS = {
    "php": ("/<\\?(?:php|=)/", "php"),
    "asp": ("/<%|runat\\s*=\\s*[\"']server/ nocase", "asp"),
    "jsp": ("/<%/", "jsp"),
}
STRONG_AT = 60


def yara_regex(sig: Sig) -> str | None:
    pat = sig.rx.pattern
    if not re2_compatible(pat):
        return None
    return "/" + pat.replace("/", "\\/") + "/is"


def _group_rule(group: str, sigs: list[Sig], strong: bool) -> str | None:
    strings: list[str] = []
    meta_ids: list[str] = []
    for i, s in enumerate(sigs):
        rx = yara_regex(s)
        if rx:
            strings.append(f"        $s{i} = {rx}")
            meta_ids.append(s.id)
    if not strings:
        return None
    tag, _ = TAGS[group]
    cond = "any of ($s*)" if strong else "2 of ($s*)"
    name = f"iisguard_{group}_webshell_{'strong' if strong else 'weak'}"
    return (
        f'rule {name} {{\n    meta:\n        description = "iisguard {group.upper()} web-shell indicators ({"any one" if strong else "two or more"})"\n'
        f'        author = "iisguard contributors"\n        signatures = "{",".join(meta_ids)}"\n'
        '        reference = "https://github.com/qmmughal/iisguard"\n    strings:\n'
        f"        $tag = {tag}\n"
        + "\n".join(strings)
        + f"\n    condition:\n        filesize < 2MB and $tag and {cond}\n}}\n"
    )


EXTRA = """rule iisguard_php_auto_prepend_config {
    meta:
        description = "PHP config (.user.ini / .htaccess) that injects a file into every PHP request"
        author = "iisguard contributors"
    strings:
        $a = /(^|\\n)\\s*(php_(admin_)?value\\s+)?auto_(prepend|append)_file[ \\t]*=?[ \\t]*[^\\s]/ nocase
    condition:
        filesize < 16KB and $a
}

rule iisguard_script_inside_image {
    meta:
        description = "Image-like file (PNG/GIF/JPEG header) carrying server-side script"
        author = "iisguard contributors"
    strings:
        $php = /<\\?php\\s/ nocase
        $asp = /<%@\\s*(Page|Control|WebHandler)/ nocase
    condition:
        (uint32be(0) == 0x89504E47 or uint32be(0) == 0x47494638 or uint16be(0) == 0xFFD8) and ($php or $asp)
}
"""


def export() -> str:
    parts = ["// iisguard YARA rules (generated). Detect-only; tune before using as a block signal.\n"]
    for group in ("php", "asp", "jsp"):
        sigs = [s for s in SIGS if s.group == group]
        strong = [s for s in sigs if s.score >= STRONG_AT]
        weak = [s for s in sigs if s.score < STRONG_AT and not re.search(r"request-(input|param)$", s.id)]
        for rule in (_group_rule(group, strong, True), _group_rule(group, weak, False)):
            if rule:
                parts.append(rule)
    parts.append(EXTRA)
    return "\n".join(parts)
