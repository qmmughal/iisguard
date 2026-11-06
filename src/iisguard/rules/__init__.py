"""Rule loading and the matching engine.

rules.yaml is a versioned pack. Each rule carries its own tests (``match`` /
``no_match`` sample strings) which pytest runs against the compiled pattern, so a
community-submitted rule cannot be merged without proof that it fires and that it
leaves benign input alone.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from importlib import resources
from pathlib import Path
from typing import Any

from iisguard import miniyaml
from iisguard.models import RULE_FIELDS, SEVERITIES, LogEvent, Rule

_ALLOWED_KEYS = {
    "id", "category", "score", "severity", "field", "pattern", "description",
    "cve", "enabled", "methods", "tests", "exclude",
}  # fmt: skip
_REQUIRED_KEYS = {"id", "category", "score", "severity", "field", "pattern", "tests"}
_FIELD_ATTR = {"line": "raw"}
_MEMO_FIELDS = {"ua", "path"}


class RuleError(ValueError):
    pass


def _load_text(path: str | None) -> tuple[str, str]:
    if path:
        return Path(path).read_text(encoding="utf-8-sig"), path
    text = resources.files("iisguard.rules").joinpath("rules.yaml").read_text(encoding="utf-8")
    return text, "bundled rules.yaml"


def _parse_yaml(text: str, origin: str) -> Any:
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        pass
    except Exception as e:  # yaml.YAMLError without importing at module level
        raise RuleError(f"{origin}: {e}") from e
    try:
        return miniyaml.loads(text)
    except miniyaml.YamlError as e:
        raise RuleError(f"{origin}: {e}") from e


def load_rules(path: str | None = None, disabled: Iterable[str] = ()) -> list[Rule]:
    """Load rules from *path*, else an installed update-rules pack, else the bundled pack."""
    if path is None:
        from iisguard.state import state_dir

        user = state_dir() / "rules" / "web-core" / "rules.yaml"
        if user.is_file():
            try:
                return _load(str(user), disabled)
            except (RuleError, OSError):
                pass  # a broken update must never disable detection: use the bundled pack
    return _load(path, disabled)


def _load(path: str | None, disabled: Iterable[str]) -> list[Rule]:
    text, origin = _load_text(path)
    data = _parse_yaml(text, origin)
    if isinstance(data, dict):
        data = data.get("rules")
    if not isinstance(data, list):
        raise RuleError(f"{origin}: expected a list of rules (or a 'rules:' list)")
    off = set(disabled)
    rules: list[Rule] = []
    seen: set[str] = set()
    for i, item in enumerate(data, 1):
        if not isinstance(item, dict):
            raise RuleError(f"{origin}: rule #{i} is not a mapping")
        rid = str(item.get("id", f"#{i}"))
        unknown = set(item) - _ALLOWED_KEYS
        missing = _REQUIRED_KEYS - set(item)
        if unknown:
            raise RuleError(f"{origin}: rule {rid}: unknown keys {sorted(unknown)}")
        if missing:
            raise RuleError(f"{origin}: rule {rid}: missing keys {sorted(missing)}")
        if rid in seen:
            raise RuleError(f"{origin}: duplicate rule id {rid}")
        seen.add(rid)
        if item["severity"] not in SEVERITIES:
            raise RuleError(f"{origin}: rule {rid}: severity must be one of {SEVERITIES}")
        if item["field"] not in RULE_FIELDS or item["field"] == "behavior":
            raise RuleError(f"{origin}: rule {rid}: field must be one of {RULE_FIELDS[:-1]}")
        if not isinstance(item["score"], int) or not 0 <= item["score"] <= 1000:
            raise RuleError(f"{origin}: rule {rid}: score must be an integer 0..1000")
        tests = item["tests"] or {}
        t_match = list(tests.get("match") or [])
        t_no = list(tests.get("no_match") or [])
        if not t_match or not t_no:
            raise RuleError(f"{origin}: rule {rid}: tests need at least one match and one no_match sample")
        try:
            rx = re.compile(str(item["pattern"]), re.IGNORECASE)
        except re.error as e:
            raise RuleError(f"{origin}: rule {rid}: bad pattern: {e}") from e
        rules.append(
            Rule(
                id=rid,
                category=str(item["category"]),
                score=item["score"],
                severity=item["severity"],
                field=item["field"],
                pattern=str(item["pattern"]),
                description=str(item.get("description") or ""),
                cve=[str(c) for c in (item.get("cve") or [])],
                enabled=bool(item.get("enabled", True)) and rid not in off,
                methods=[str(m).upper() for m in (item.get("methods") or [])],
                tests_match=[str(t) for t in t_match],
                tests_no_match=[str(t) for t in t_no],
                rx=rx,
                exclude=str(item.get("exclude") or ""),
                exclude_rx=_compile_exclude(item.get("exclude"), rid, origin),
            )
        )
    return rules


def _compile_exclude(value: Any, rid: str, origin: str) -> re.Pattern[str] | None:
    if not value:
        return None
    try:
        return re.compile(str(value), re.IGNORECASE)
    except re.error as e:
        raise RuleError(f"{origin}: rule {rid}: bad exclude pattern: {e}") from e


def sample_matches(rule: Rule, sample: str) -> bool:
    """True when the rule fires on *sample* (pattern matches and no exclude matches). Used by the rule tests."""
    s = sample.replace("<LONG1000>", "A" * 1000)
    assert rule.rx is not None
    return bool(rule.rx.search(s)) and not (rule.exclude_rx and rule.exclude_rx.search(s))


class RuleSet:
    """Fast matcher: one combined pre-filter regex per field, per-rule check only on a hit."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = [r for r in rules if r.enabled]
        by_field: dict[str, list[Rule]] = {}
        for r in self.rules:
            by_field.setdefault(r.field, []).append(r)
        # (event attribute, combined pre-filter, rules, memo of pre-filter results or None)
        self._groups: list[tuple[str, re.Pattern[str], list[Rule], dict[str, bool] | None]] = []
        for f, group in by_field.items():
            combined = re.compile("|".join(f"(?:{r.pattern})" for r in group), re.IGNORECASE)
            memo: dict[str, bool] | None = {} if f in _MEMO_FIELDS else None
            self._groups.append((_FIELD_ATTR.get(f, f), combined, group, memo))

    def match(self, ev: LogEvent) -> list[Rule]:
        out: list[Rule] = []
        for attr, pre, group, memo in self._groups:
            val: str = getattr(ev, attr)
            if not val:
                continue
            if memo is not None:  # user agents and paths repeat heavily in real logs
                ok = memo.get(val)
                if ok is None:
                    if len(memo) > 100_000:
                        memo.clear()
                    ok = memo[val] = pre.search(val) is not None
            else:
                ok = pre.search(val) is not None
            if ok:
                for r in group:
                    if r.methods and ev.method not in r.methods:
                        continue
                    if r.rx is not None and r.rx.search(val) and not (r.exclude_rx and r.exclude_rx.search(val)):
                        out.append(r)
        return out
