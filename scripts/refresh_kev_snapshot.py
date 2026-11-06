"""Developer tool: refresh the bundled KEV snapshot used by `iisguard audit --offline`.

    python scripts/refresh_kev_snapshot.py [path-to-full-kev.json]

With no argument it downloads the live CISA feed (network). Review the diff before committing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from iisguard.audit.kev import KEV_URL, _download, build_snapshot

OUT = Path(__file__).resolve().parent.parent / "src" / "iisguard" / "audit" / "data" / "kev_snapshot.json"

raw = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")) if len(sys.argv) > 1 else _download(KEV_URL)
snap = build_snapshot(raw)
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(snap, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {OUT} ({snap['count']} web-facing entries, catalog {snap['catalogVersion']})")
