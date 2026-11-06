"""Version parsing and comparison (PHP, .NET, WordPress, Windows build numbers)."""

from __future__ import annotations

import re
from functools import total_ordering

_RX = re.compile(r"^[vV]?(\d+(?:\.\d+)*)(.*)$")
_PRE = re.compile(r"(alpha|beta|rc|dev|preview|pre|snapshot)[.\-]?(\d*)", re.IGNORECASE)
_DISTRO = re.compile(r"ubuntu|debian|\bdeb\d|\+deb|~|\.el\d|\.fc\d|\.amzn|\.module|\.rhel|\.sles|esm", re.IGNORECASE)


class VersionError(ValueError):
    pass


@total_ordering
class Version:
    """Numeric dotted version; pre-releases (8.3.0RC1, 11.0.0-preview.2) sort before the release."""

    __slots__ = ("nums", "pre", "raw")

    def __init__(self, raw: str) -> None:
        m = _RX.match(raw.strip())
        if not m:
            raise VersionError(f"unparseable version: {raw!r}")
        self.raw = raw.strip()
        self.nums = tuple(int(p) for p in m.group(1).split("."))
        pm = _PRE.search(m.group(2))
        self.pre: tuple[str, int] | None = (pm.group(1).lower(), int(pm.group(2) or 0)) if pm else None

    def _key(self, width: int) -> tuple[tuple[int, ...], int, str, int]:
        nums = self.nums + (0,) * (width - len(self.nums))
        if self.pre is None:
            return (nums, 1, "", 0)
        return (nums, 0, self.pre[0], self.pre[1])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        w = max(len(self.nums), len(other.nums))
        return self._key(w) == other._key(w)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        w = max(len(self.nums), len(other.nums))
        return self._key(w) < other._key(w)

    def __hash__(self) -> int:
        return hash(self._key(len(self.nums)))

    def branch(self, parts: int = 2) -> str:
        return ".".join(str(n) for n in self.nums[:parts])

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"


def parse_version(raw: str) -> Version:
    return Version(raw)


def is_distro_build(raw: str) -> bool:
    """Distro packages (Debian/Ubuntu/RHEL...) backport fixes without bumping the upstream version."""
    return bool(_DISTRO.search(raw))
