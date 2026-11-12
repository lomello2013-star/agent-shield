"""Safe mode, config validation and last-known-good (reliability.md §3, п.6).

Any config/rule/model that fails validation must not be applied: the platform
keeps the last-known-good state and enters safe mode with a reason, so a bad
release cannot brick protection.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any


class ConfigError(ValueError):
    """Raised when configuration does not match the schema."""


# Strict top-level schema: unknown keys are rejected (typos are dangerous).
CONFIG_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "schema_version": str,
    "sources": list,
    "thresholds": dict,
    "queue": dict,
    "watchdog": dict,
    "allowlist": list,
}

REQUIRED_KEYS = ("schema_version", "sources", "thresholds")


def validate_config(cfg: Any, schema: dict[str, type | tuple[type, ...]] | None = None) -> None:
    """Validate configuration shape. Raises ConfigError with the offending path."""
    schema = schema or CONFIG_SCHEMA
    if not isinstance(cfg, dict):
        raise ConfigError("config must be an object")
    unknown = sorted(set(cfg) - set(schema))
    if unknown:
        raise ConfigError(f"unknown config keys: {unknown}")
    for key in REQUIRED_KEYS:
        if key not in cfg:
            raise ConfigError(f"missing required key: {key}")
    for key, expected in schema.items():
        if key in cfg and not isinstance(cfg[key], expected):
            names = expected.__name__ if isinstance(expected, type) else "/".join(t.__name__ for t in expected)
            raise ConfigError(f"{key}: expected {names}, got {type(cfg[key]).__name__}")
    for i, src in enumerate(cfg["sources"]):
        if not isinstance(src, str) or not src:
            raise ConfigError(f"sources[{i}] must be a non-empty string")
    for name, value in cfg["thresholds"].items():
        if not isinstance(name, str) or not isinstance(value, (int, float)):
            raise ConfigError(f"thresholds[{name}] must be numeric")
        if value < 0:
            raise ConfigError(f"thresholds[{name}] must be non-negative")


def config_fingerprint(cfg: dict) -> str:
    payload = json.dumps(cfg, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ApplyResult:
    accepted: bool
    mode: str            # "normal" | "safe"
    reason: str
    fingerprint: str | None
    dry_run: bool


class SafeMode:
    """Last-known-good store + safe-mode state machine.

    Layout: ``<root>/lkg/config.json`` + ``<root>/lkg/config.sha256``.
    """

    def __init__(self, root: str, now_fn=None) -> None:
        self.root = os.path.abspath(root)
        self.lkg_dir = os.path.join(self.root, "lkg")
        self._safe = False
        self.reason = ""
        self._now = now_fn

    # ---------------- last known good ----------------
    def save_lkg(self, cfg: dict) -> str:
        validate_config(cfg)
        os.makedirs(self.lkg_dir, exist_ok=True)
        fp = config_fingerprint(cfg)
        cfg_path = os.path.join(self.lkg_dir, "config.json")
        tmp = cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False, sort_keys=True, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, cfg_path)
        with open(os.path.join(self.lkg_dir, "config.sha256"), "w", encoding="utf-8") as fh:
            fh.write(fp)
            fh.flush()
            os.fsync(fh.fileno())
        return fp

    def load_lkg(self) -> dict | None:
        cfg_path = os.path.join(self.lkg_dir, "config.json")
        fp_path = os.path.join(self.lkg_dir, "config.sha256")
        if not (os.path.exists(cfg_path) and os.path.exists(fp_path)):
            return None
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        with open(fp_path, "r", encoding="utf-8") as fh:
            expected = fh.read().strip()
        if config_fingerprint(cfg) != expected:
            raise ConfigError("last-known-good config checksum mismatch")
        validate_config(cfg)
        return cfg

    # ---------------- apply ----------------
    def apply(self, cfg: dict, dry_run: bool = True) -> ApplyResult:
        """Validate and (if accepted) persist config. Dry-run never mutates state."""
        try:
            validate_config(cfg)
        except ConfigError as exc:
            self.enter(f"invalid config: {exc}")
            return ApplyResult(False, "safe", f"invalid config: {exc}", None, dry_run)
        fp = config_fingerprint(cfg)
        if dry_run:
            return ApplyResult(True, "safe" if self._safe else "normal", "dry-run ok", fp, True)
        try:
            self.save_lkg(cfg)
        except OSError as exc:
            self.enter(f"cannot persist config: {exc}")
            return ApplyResult(False, "safe", f"cannot persist config: {exc}", fp, False)
        return ApplyResult(True, "safe" if self._safe else "normal", "applied", fp, False)

    # ---------------- state machine ----------------
    def enter(self, reason: str) -> None:
        self._safe = True
        self.reason = reason

    def exit(self, operator: bool) -> bool:
        """Safe mode may only be exited by an operator (не «само вылечивается»)."""
        if not operator:
            return False
        self._safe = False
        self.reason = ""
        return True

    @property
    def is_safe(self) -> bool:
        return self._safe

    def status(self) -> dict[str, object]:
        return {"safe_mode": self._safe, "reason": self.reason}
