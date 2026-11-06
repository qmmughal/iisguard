"""Tail log files, score attackers continuously, and (with --live) keep the firewall block list in sync."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from iisguard.analyzer import Analyzer
from iisguard.config import Config
from iisguard.firewall.manager import BlockManager, SyncResult
from iisguard.firewall.safety import Protector
from iisguard.logs import FORMAT_ALIASES, PARSERS, detect_format
from iisguard.models import ParseStats
from iisguard.rules import RuleSet


class Tailer:
    """Poll-based tail that survives truncation and rotation. Starts at the end of the file by default."""

    def __init__(self, path: str, fmt: str = "auto", from_start: bool = False) -> None:
        self.path = path
        self.fmt = FORMAT_ALIASES.get(fmt, fmt)
        self.offset = 0
        self.inode: int | None = None
        self.header: list[str] = []  # IIS '#Fields:' lines, re-fed with every chunk
        self.buf = b""
        self._open(from_start)

    def _open(self, from_start: bool) -> None:
        try:
            st = os.stat(self.path)
        except OSError:
            self.offset, self.inode = 0, None
            return
        self.inode = st.st_ino
        with open(self.path, "rb") as f:
            head = f.read(65536).decode("latin-1").splitlines()
        if self.fmt == "auto":
            self.fmt = detect_format(head) or "auto"
        self.header = [ln for ln in head[:60] if ln.startswith(("#Fields:", "#Software", "#Version"))][:4]
        self.offset = 0 if from_start else st.st_size

    def read_new(self) -> list[str]:
        try:
            st = os.stat(self.path)
        except OSError:
            return []
        if (self.inode is not None and st.st_ino != self.inode and st.st_ino != 0) or st.st_size < self.offset:
            self.offset, self.inode, self.buf = (
                0,
                st.st_ino,
                b"",
            )  # rotated or truncated: read the new file from the top
        elif self.inode is None:
            self._open(True)
        if st.st_size == self.offset:
            return []
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            data = f.read(8 * 1024 * 1024)
        self.offset += len(data)
        data = self.buf + data
        *complete, self.buf = data.split(b"\n")  # keep a partial last line for the next poll
        return [ln.decode("latin-1") + "\n" for ln in complete]


@dataclass
class Watcher:
    cfg: Config
    rules: RuleSet
    files: list[str]
    manager: BlockManager
    protector: Callable[[], Protector]
    fmt: str = "auto"
    live: bool = False
    from_start: bool = False
    sync_interval: float = 30.0
    window_seconds: float = 86400.0
    clock: Callable[[], float] = time.time
    log: Callable[[str], None] = print
    tailers: list[Tailer] = field(default_factory=list)
    stats: ParseStats = field(default_factory=ParseStats)

    def __post_init__(self) -> None:
        self.tailers = [Tailer(f, self.fmt, self.from_start) for f in self.files]
        self._reset()
        self._last_sync = 0.0

    def _reset(self) -> None:
        self.analyzer = Analyzer(self.rules, self.cfg, self.protector())
        self._window_start = self.clock()

    def step(self) -> SyncResult | None:
        """Read new lines, feed the analyzer, and sync when the interval has elapsed. Returns the sync result if one ran."""
        for t in self.tailers:
            lines = t.read_new()
            if not lines:
                continue
            parser = PARSERS.get(t.fmt)
            if parser is None:
                continue
            for ev in parser(t.header + lines if t.fmt == "iis" else lines, self.stats):
                self.analyzer.feed(ev)
        now = self.clock()
        if now - self._last_sync < self.sync_interval:
            return None
        self._last_sync = now
        rep = self.analyzer.finish()
        blocks: list[dict[str, Any]] = rep.blocks
        res = self.manager.sync(blocks, live=self.live)
        if res.added or res.removed or res.warnings:
            mode = "LIVE" if self.live else "dry-run"
            self.log(
                f"[{mode}] +{len(res.added)} -{len(res.removed)} protected={len(res.protected)} total={len(res.ips)}"
            )
            for w in res.warnings:
                self.log(f"warning: {w}")
        if now - self._window_start > self.window_seconds:
            self._reset()  # forget old scores; the manager's TTL expires old blocks
        return res

    def run(self, poll: float = 2.0, max_steps: int | None = None, sleep: Callable[[float], None] = time.sleep) -> None:
        n = 0
        try:
            while max_steps is None or n < max_steps:
                self.step()
                n += 1
                sleep(poll)
        except KeyboardInterrupt:
            self.log("stopped")
