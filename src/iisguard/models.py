"""Core data types shared across modules."""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

#: Event attributes a rule may target. ``line`` maps to the raw log line.
RULE_FIELDS = ("uri", "path", "query", "ua", "method", "message", "line", "behavior")


@dataclass(slots=True)
class LogEvent:
    """One parsed log record (web access line or PHP/web-server error line)."""

    ts: float = 0.0  # epoch seconds, UTC; 0.0 if unknown
    ip: str = ""
    method: str = ""
    uri: str = ""  # percent-decoded path + "?" + query
    path: str = ""
    query: str = ""
    status: int = 0
    ua: str = ""
    message: str = ""  # error-log text
    level: str = ""  # error-log level: fatal / parse / warning / crash ...
    raw: str = ""


@dataclass(eq=False)
class Rule:
    id: str
    category: str
    score: int
    severity: str
    field: str
    pattern: str
    description: str = ""
    cve: list[str] = dataclasses.field(default_factory=list)
    enabled: bool = True
    methods: list[str] = dataclasses.field(default_factory=list)
    tests_match: list[str] = dataclasses.field(default_factory=list)
    tests_no_match: list[str] = dataclasses.field(default_factory=list)
    rx: re.Pattern[str] | None = None

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class Hit:
    """Aggregated detections of one rule by one source IP."""

    ip: str
    rule_id: str
    category: str
    severity: str
    score: int
    count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    samples: list[str] = dataclasses.field(default_factory=list)
    cve: list[str] = dataclasses.field(default_factory=list)


@dataclass
class ParseStats:
    lines: int = 0
    events: int = 0
    bad: int = 0
    formats: dict[str, int] = dataclasses.field(default_factory=dict)
