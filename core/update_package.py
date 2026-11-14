"""Signed update bundle for the A/B slot updater.

Format (JSON, transport agnostic)::

    {
      "version": "1.2.0",
      "files": {"bin/aidfd": "<base64>", "rules/base.json": "<base64>"},
      "manifest": {"version": "1.2.0", "files": {"bin/aidfd": "<sha256>"}},
      "signature": "<base64 Ed25519 over canonical manifest>"
    }

The signature covers the manifest only; every file is checked against the
manifest before anything is written to the inactive slot. This is the same
shape used by ``stml-connector sign-package`` for fleet releases, but with a
self-contained bundle for the local agent installer/updater.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.updater import DualSlot, UpdateError


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_manifest(version: str, files: dict[str, bytes]) -> dict:
    return {"version": str(version),
            "files": {name: sha256(data) for name, data in sorted(files.items())}}


def _canonical_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_bundle(version: str, files: dict[str, bytes], private_key_pem: bytes) -> dict:
    manifest = canonical_manifest(version, files)
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise UpdateError("update signing key must be Ed25519")
    signature = key.sign(_canonical_bytes(manifest))
    return {
        "version": str(version),
        "files": {name: base64.b64encode(data).decode("ascii")
                  for name, data in files.items()},
        "manifest": manifest,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_bundle(bundle: dict, public_key_pem: bytes) -> dict[str, bytes]:
    if not isinstance(bundle, dict):
        raise UpdateError("bundle must be an object")
    manifest = bundle.get("manifest")
    signature = bundle.get("signature")
    if not isinstance(manifest, dict) or not isinstance(signature, str):
        raise UpdateError("bundle lacks manifest/signature")
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise UpdateError("update public key must be Ed25519")
    try:
        key.verify(base64.b64decode(signature), _canonical_bytes(manifest))
    except Exception as exc:  # noqa: BLE001 - cryptography raises several types
        raise UpdateError(f"update signature rejected: {exc}") from exc

    encoded = bundle.get("files")
    if not isinstance(encoded, dict):
        raise UpdateError("bundle lacks files")
    files: dict[str, bytes] = {}
    for name, value in encoded.items():
        try:
            data = base64.b64decode(value, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise UpdateError(f"invalid base64 for {name}: {exc}") from exc
        expected = manifest.get("files", {}).get(name)
        if expected != sha256(data):
            raise UpdateError(f"file hash mismatch: {name}")
        files[str(name)] = data
    if set(files) != set(manifest.get("files", {})):
        raise UpdateError("manifest/file set mismatch")
    return files


def apply_bundle(slot_root: str, bundle: dict, public_key_pem: bytes,
                 health: Callable[[], bool] | None = None) -> dict:
    files = verify_bundle(bundle, public_key_pem)
    slot = DualSlot(slot_root)
    version = str(bundle.get("version") or bundle["manifest"].get("version"))
    if health is None:
        staged = slot.stage(version, files)
        pointer = slot.activate(staged["slot"], version)
        return {"result": "updated", "slot": pointer["slot"], "version": version}
    return slot.update_with_health_gate(version, files, health)


def bundle_to_file(bundle: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def bundle_from_file(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
