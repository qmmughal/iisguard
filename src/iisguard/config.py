"""Configuration: JSON or YAML file, environment overrides, validation."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iisguard import miniyaml


class ConfigError(ValueError):
    pass


DEFAULT_LOGIN_PATHS = [
    r"/wp-login\.php",
    r"/xmlrpc\.php",
    r"/owa/auth\.owa",
    r"/ecp/default\.aspx",
    r"/account/login",
    r"/user/login",
    r"/users/sign_in",
    r"/admin/login",
    r"/administrator/index\.php",
    r"/login",
    r"/api/(?:auth|login|token)",
]


@dataclass
class Config:
    # --- protection (never block) ---
    allowlist: list[str] = field(default_factory=list)
    cdn_ranges: list[str] = field(default_factory=list)  # extra, on top of bundled lists
    admin_ips: list[str] = field(default_factory=list)  # extra, on top of auto-detected
    self_ips: list[str] = field(default_factory=list)
    protect_private: bool = True
    detect_admin: bool = True
    # --- decisions ---
    block_score: int = 100
    max_blocks: int = 500
    # --- behaviour thresholds ---
    login_paths: list[str] = field(default_factory=lambda: list(DEFAULT_LOGIN_PATHS))
    spray_window: int = 600  # seconds
    spray_min_ips: int = 10  # distinct IPs hitting one login path...
    spray_per_ip_max: int = 5  # ...each with at most this many attempts
    brute_attempts: int = 10  # attempts by ONE ip inside spray_window
    flood_requests: int = 150
    flood_window: int = 10
    scan4xx_count: int = 25
    scan4xx_window: int = 60
    crash_burst_count: int = 10
    crash_burst_window: int = 120
    subnet_min_ips: int = 5
    # --- rules ---
    rules_path: str = ""
    disabled_rules: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


_INT_FIELDS = {
    "block_score": (1, 100000),
    "max_blocks": (1, 1000000),
    "spray_window": (1, 86400),
    "spray_min_ips": (2, 100000),
    "spray_per_ip_max": (1, 1000),
    "brute_attempts": (2, 100000),
    "flood_requests": (5, 10000000),
    "flood_window": (1, 3600),
    "scan4xx_count": (3, 1000000),
    "scan4xx_window": (1, 86400),
    "crash_burst_count": (2, 100000),
    "crash_burst_window": (1, 86400),
    "subnet_min_ips": (2, 100000),
}
_BOOL_FIELDS = {"protect_private", "detect_admin"}
_LIST_FIELDS = {"allowlist", "cdn_ranges", "admin_ips", "self_ips", "login_paths", "disabled_rules"}
_STR_FIELDS = {"rules_path"}
_ENV_PREFIX = "IISGUARD_"


def _load_file(path: Path) -> Mapping[str, Any]:
    text = path.read_text(encoding="utf-8-sig")
    try:
        if path.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml

                data = yaml.safe_load(text)
            except ImportError:
                data = miniyaml.loads(text)
        else:
            data = json.loads(text)
    except (ValueError, miniyaml.YamlError) as e:
        raise ConfigError(f"{path}: {e}") from e
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def _apply(cfg: Config, data: Mapping[str, Any], origin: str) -> None:
    for key, value in data.items():
        if key in _INT_FIELDS:
            lo, hi = _INT_FIELDS[key]
            if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
                raise ConfigError(f"{origin}: {key} must be an integer in {lo}..{hi}, got {value!r}")
            setattr(cfg, key, value)
        elif key in _BOOL_FIELDS:
            if not isinstance(value, bool):
                raise ConfigError(f"{origin}: {key} must be true/false, got {value!r}")
            setattr(cfg, key, value)
        elif key in _LIST_FIELDS:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ConfigError(f"{origin}: {key} must be a list of strings")
            setattr(cfg, key, list(value))
        elif key in _STR_FIELDS:
            if not isinstance(value, str):
                raise ConfigError(f"{origin}: {key} must be a string")
            setattr(cfg, key, value)
        else:
            cfg.warnings.append(f"{origin}: unknown setting {key!r} ignored")


def _env_overrides(env: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, raw in env.items():
        if not key.startswith(_ENV_PREFIX):
            continue
        name = key[len(_ENV_PREFIX) :].lower()
        if name in _INT_FIELDS:
            try:
                out[name] = int(raw)
            except ValueError as e:
                raise ConfigError(f"{key}: not an integer: {raw!r}") from e
        elif name in _BOOL_FIELDS:
            if raw.lower() not in ("1", "0", "true", "false", "yes", "no"):
                raise ConfigError(f"{key}: expected true/false, got {raw!r}")
            out[name] = raw.lower() in ("1", "true", "yes")
        elif name in _LIST_FIELDS:
            out[name] = [p.strip() for p in raw.split(",") if p.strip()]
        elif name in _STR_FIELDS:
            out[name] = raw
    return out


def validate(cfg: Config) -> None:
    for name in ("allowlist", "cdn_ranges"):
        for item in getattr(cfg, name):
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as e:
                raise ConfigError(f"{name}: invalid IP/CIDR {item!r}") from e
    for name in ("admin_ips", "self_ips"):
        for item in getattr(cfg, name):
            try:
                ipaddress.ip_address(item)
            except ValueError as e:
                raise ConfigError(f"{name}: invalid IP {item!r}") from e
    for p in cfg.login_paths:
        try:
            re.compile(p)
        except re.error as e:
            raise ConfigError(f"login_paths: bad regex {p!r}: {e}") from e


def load_config(
    path: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    search_dir: Path | None = None,
) -> Config:
    """Defaults < config file < IISGUARD_* environment variables."""
    cfg = Config()
    file_path: Path | None = Path(path) if path else None
    if file_path is None:
        base = search_dir or Path.cwd()
        for name in ("iisguard.json", "iisguard.yaml", "iisguard.yml"):
            if (base / name).is_file():
                file_path = base / name
                break
    elif not file_path.is_file():
        raise ConfigError(f"config file not found: {file_path}")
    if file_path is not None:
        _apply(cfg, _load_file(file_path), str(file_path))
    _apply(cfg, _env_overrides(os.environ if env is None else env), "environment")
    validate(cfg)
    return cfg
