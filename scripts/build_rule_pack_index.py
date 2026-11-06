"""Developer tool: publish the bundled rules as rule-packs/web-core and rebuild rule-packs/index.json.

    python scripts/build_rule_pack_index.py

Bump src/iisguard/rules/VERSION first (format YYYY.MM.DD-N). `iisguard update-rules` installs a pack only if its
version is newer than the installed one, after verifying the SHA-256 and running every rule's own tests.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

root = Path(__file__).resolve().parent.parent
src = root / "src" / "iisguard" / "rules"
pack = root / "rule-packs" / "web-core"
pack.mkdir(parents=True, exist_ok=True)
shutil.copyfile(src / "rules.yaml", pack / "rules.yaml")
data = (pack / "rules.yaml").read_bytes()
index = {
    "schema": 1,
    "packs": [
        {
            "name": "web-core",
            "version": (src / "VERSION").read_text(encoding="utf-8").strip(),
            "file": "web-core/rules.yaml",
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    ],
}
(root / "rule-packs" / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
print("rule-packs/index.json:", index["packs"][0]["version"], index["packs"][0]["sha256"][:12])
