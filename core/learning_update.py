"""LearningUpdate delivery: verify and persist; rule/model application is separate."""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

SIGNED_FIELDS = ("update_id", "version", "rules", "model_packs", "qa_pairs",
                 "task_solutions", "kb_version")


def canonical_update(update: dict[str, Any]) -> bytes:
    body = {key: update[key] for key in SIGNED_FIELDS if key in update}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def verify_update(update: dict[str, Any], pubkey_pem: str) -> None:
    key = load_pem_public_key(pubkey_pem.encode())
    try:
        signature = base64.b64decode(str(update.get("signature", "")), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("bad learning-update signature encoding") from exc
    try:
        key.verify(signature, canonical_update(update))  # type: ignore[attr-defined]
    except InvalidSignature as exc:
        raise ValueError("bad learning-update signature") from exc


def apply_update(daemon, update: dict[str, Any], pubkey_pem: str) -> dict[str, Any]:
    verify_update(update, pubkey_pem)
    path = os.path.join(daemon.root, "learning_updates.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
        if not isinstance(stored, list):
            stored = []
    except (OSError, json.JSONDecodeError):
        stored = []
    if not any(u.get("update_id") == update.get("update_id") for u in stored):
        stored.append(update)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(stored, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    daemon.log.append("learning_update", {"update_id": update.get("update_id"),
                                         "version": update.get("version"),
                                         "stored": len(stored)})
    return {"status": "acked", "stored": len(stored), "applied": False,
            "update_id": update.get("update_id"),
            "received_at": datetime.now(timezone.utc).isoformat()}
