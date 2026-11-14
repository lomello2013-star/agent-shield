"""Signed policy state for the agent (Phase B).

The server signs a canonical policy document; the agent verifies it before
persisting. Applying a policy updates the last-known-good config, but live
detector reload is deliberately explicit (next daemon start) until a controlled
reload is implemented.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

from core.safemode import ConfigError, validate_config


def canonical_policy(policy: dict[str, Any]) -> bytes:
    body = {"policy_id": policy.get("policy_id", ""),
            "version": policy.get("version", ""),
            "channel": policy.get("channel", "stable"),
            "content": policy.get("content", {})}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def key_id(pubkey_pem: str) -> str:
    key = load_pem_public_key(pubkey_pem.encode())
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)  # type: ignore[attr-defined]
    return hashlib.sha256(raw).hexdigest()[:16]


def verify_policy(policy: dict[str, Any], pubkey_pem: str) -> None:
    if not pubkey_pem:
        raise ValueError("policy pubkey not configured")
    if str(policy.get("key_id", "")) != key_id(pubkey_pem):
        raise ValueError("policy key_id mismatch")
    try:
        sig = base64.b64decode(str(policy.get("signature", "")), validate=True)
    except Exception as exc:  # noqa: BLE001 - malformed input
        raise ValueError("bad policy signature encoding") from exc
    key = load_pem_public_key(pubkey_pem.encode())
    try:
        key.verify(sig, canonical_policy(policy))  # type: ignore[attr-defined]
    except InvalidSignature as exc:
        raise ValueError("bad policy signature") from exc


class PolicyStore:
    def __init__(self, root: str) -> None:
        self.path = os.path.join(root, "policy_state.json")

    def load(self) -> dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def save(self, state: dict[str, Any]) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, sort_keys=True, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def state(self, daemon) -> dict[str, Any]:
        state = self.load()
        return {"policy_id": state.get("policy_id"),
                "version": state.get("version"),
                "channel": state.get("channel"),
                "fingerprint": state.get("fingerprint"),
                "applied_at": state.get("applied_at"),
                "live": False,
                "safe_mode": daemon.safe_mode.status()}

    def apply(self, daemon, policy: dict[str, Any], pubkey_pem: str,
              dry_run: bool = True) -> dict[str, Any]:
        verify_policy(policy, pubkey_pem)
        content = policy.get("content")
        if not isinstance(content, dict):
            raise ValueError("policy content must be object")
        try:
            validate_config(content)
        except ConfigError as exc:
            return {"accepted": False, "dry_run": dry_run,
                    "reason": f"invalid config: {exc}"}
        fingerprint = hashlib.sha256(canonical_policy(policy)).hexdigest()
        result = {"accepted": True, "dry_run": dry_run,
                  "policy_id": policy.get("policy_id"),
                  "version": policy.get("version"),
                  "fingerprint": fingerprint, "live": False}
        if dry_run:
            return result
        applied = daemon.safe_mode.apply(content, dry_run=False)
        if not applied.accepted:
            return {"accepted": False, "dry_run": False,
                    "reason": applied.reason, "fingerprint": fingerprint}
        state = {"policy_id": policy.get("policy_id"),
                 "version": policy.get("version"),
                 "channel": policy.get("channel", "stable"),
                 "key_id": policy.get("key_id", ""),
                 "fingerprint": fingerprint,
                 "applied_at": datetime.now(timezone.utc).isoformat()}
        self.save(state)
        daemon.log.append("policy_applied", {"policy_id": state["policy_id"],
                                            "version": state["version"],
                                            "fingerprint": fingerprint})
        return {**result, "config_fingerprint": applied.fingerprint}
