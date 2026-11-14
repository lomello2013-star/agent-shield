"""Signed connector package manifests (verify before running a new version)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from stml.connector.signing import key_id, sign, verify

SCHEMA = "stml/package/v0"
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache"}


def build_manifest(root: str | Path, version: str) -> dict[str, Any]:
    root = Path(root)
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        rel = path.relative_to(root).as_posix()
        files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "schema": SCHEMA,
        "version": version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
    }


def _canonical(manifest: dict[str, Any]) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_manifest(manifest: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = dict(manifest)
    signed["key_id"] = key_id(private_key.public_key())
    signed["signature"] = sign(private_key, _canonical(signed))
    return signed


def verify_manifest(
    manifest: dict[str, Any],
    public_key: Ed25519PublicKey,
    root: str | Path | None = None,
) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema") != SCHEMA:
        errors.append("bad schema")
    if manifest.get("key_id") != key_id(public_key):
        errors.append("key_id mismatch")
    signature = manifest.get("signature")
    if not isinstance(signature, str) or not verify(public_key, _canonical(manifest), signature):
        errors.append("bad signature")
    if root is not None:
        root = Path(root)
        for rel, digest in manifest.get("files", {}).items():
            path = root / rel
            if not path.is_file():
                errors.append(f"missing: {rel}")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                errors.append(f"hash mismatch: {rel}")
    return errors
