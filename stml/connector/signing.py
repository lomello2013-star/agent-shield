"""Ed25519 keys and signatures for the connector package and `stml/v0` messages."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from stml.connector.security import restrict


def generate_keypair(private_path: str | Path, public_path: str | Path) -> str:
    private = Ed25519PrivateKey.generate()
    private_path = Path(private_path)
    public_path = Path(public_path)
    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    restrict(private_path)
    restrict(public_path)
    return key_id(private.public_key())


def load_private(path: str | Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)  # type: ignore[return-value]


def load_public(path: str | Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(Path(path).read_bytes())  # type: ignore[return-value]


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def sign(private_key: Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(private_key.sign(data)).decode("ascii")


def verify(public_key: Ed25519PublicKey, data: bytes, signature: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature), data)
    except Exception:  # noqa: BLE001 - invalid signature is a normal negative result
        return False
    return True
