"""Signed ModelPack: verify before load (supply-chain gate for models).

A model is loaded only if all of the following hold:
  * the manifest validates against `schemas.v3.ModelPack`;
  * the artifact file exists and its sha256 equals the manifest;
  * the Ed25519 signature over the canonical manifest fields verifies against a
    trusted public key (production keys live in HSM/CI, not on the host).

Any failure is a hard rejection (fail-closed) with a machine-readable code.
There is no "unsigned but trusted" path: `MODELS_TRAIN_ON_DEVICE=False` and a
signed pack is the only way a model reaches the runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from schemas.v3 import ModelPack

SIGNED_FIELDS = ("model_id", "version", "platform", "format", "sha256",
                 "dataset_hash", "metrics", "limits")


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    code: str
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


def canonical_payload(pack: dict[str, Any]) -> bytes:
    """Canonical bytes that the signature covers (stable ordering, no floats magic)."""
    body = {key: pack[key] for key in SIGNED_FIELDS if key in pack}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_pack(pack: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Development/CI helper: sign the canonical manifest. Keys stay outside the agent."""
    return private_key.sign(canonical_payload(pack)).hex()


def verify_pack(pack: dict[str, Any], artifact_path: str,
                public_key: Ed25519PublicKey | None) -> VerificationResult:
    try:
        manifest = ModelPack.model_validate(pack)
    except ValidationError as exc:
        return VerificationResult(False, "invalid_manifest", str(exc))
    if manifest.format not in ("onnx", "gguf"):
        return VerificationResult(False, "unsupported_format", manifest.format)
    if public_key is None:
        return VerificationResult(False, "untrusted_key", "no trusted public key configured")
    if not os.path.exists(artifact_path):
        return VerificationResult(False, "missing_artifact", artifact_path)
    actual = sha256_file(artifact_path)
    if actual != manifest.sha256:
        return VerificationResult(False, "hash_mismatch", f"{actual} != {manifest.sha256}")
    try:
        public_key.verify(bytes.fromhex(manifest.signature), canonical_payload(pack))
    except Exception:
        return VerificationResult(False, "signature_invalid", "Ed25519 verification failed")
    return VerificationResult(True, "ok", "")


def load_public_key(hex_key: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))


def generate_dev_keypair() -> tuple[str, str]:
    """Dev-only keypair generation (CI/HSM owns production keys)."""
    private = Ed25519PrivateKey.generate()
    priv_hex = private.private_bytes_raw().hex()
    pub_hex = private.public_key().public_bytes_raw().hex()
    return priv_hex, pub_hex


def private_key_from_hex(hex_key: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_key))
