"""Software inventory items, shared by the collectors, the fixture loader and the engine."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PRODUCTS = ("php", "wordpress", "dotnet-runtime", "windows", "sharepoint", "exchange", "iis", "nginx", "apache")


@dataclass
class Item:
    product: str
    version: str
    location: str = ""
    source: str = ""  # how it was found: path | registry | cli | fixture
    extra: dict[str, Any] = field(default_factory=dict)


def load_inventory(path: str | Path) -> list[Item]:
    """Load an inventory file: ``{"items": [{"product": ..., "version": ..., ...}]}``."""
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    rows = data["items"] if isinstance(data, dict) else data
    items: list[Item] = []
    for i, r in enumerate(rows):
        if not isinstance(r, dict) or "product" not in r or "version" not in r:
            raise ValueError(f"inventory row {i}: needs 'product' and 'version'")
        if r["product"] not in PRODUCTS:
            raise ValueError(f"inventory row {i}: unknown product {r['product']!r}; use one of {PRODUCTS}")
        items.append(
            Item(
                r["product"],
                str(r["version"]),
                str(r.get("location", "")),
                str(r.get("source", "inventory-file")),
                dict(r.get("extra", {})),
            )
        )
    return items


def dump_inventory(items: list[Item]) -> str:
    return json.dumps({"items": [asdict(i) for i in items]}, indent=2)
