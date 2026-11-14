"""Trust Service (S2): SoftHSM-dev key registry, signing, approvals, revocation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from stml.connector.security import restrict
from stml.connector.signing import (
    generate_keypair,
    load_private,
    public_from_pem,
    sign as ed_sign,
    verify as ed_verify,
)
from stml.server.store import Store

KEY_CLASSES = {"root", "policy", "model", "driver", "connector"}


class TrustError(RuntimeError):
    pass


class TrustService:
    """File-backed SoftHSM for development; the interface is HSM-ready."""

    def __init__(self, store: Store, key_dir: str | Path, backend: str = "file") -> None:
        self.store = store
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        if backend not in {"file", "hsm"}:
            raise ValueError("backend must be file|hsm")
        self.backend = backend

    def create_key(self, key_class: str, rotated_from: str | None = None) -> dict[str, Any]:
        if key_class not in KEY_CLASSES:
            raise ValueError(f"unknown key class: {key_class}")
        if self.backend != "file":
            raise TrustError("HSM backend not configured; use SoftHSM-dev (file) for S2 gate")
        prefix = self.key_dir / f"{key_class}-{os.urandom(4).hex()}"
        private_path = Path(str(prefix) + ".pem")
        public_path = Path(str(prefix) + ".pub")
        kid = generate_keypair(private_path, public_path)
        public_pem = public_path.read_text(encoding="utf-8")
        restrict(private_path)
        self.store.add_key(kid, key_class, public_pem, str(private_path), rotated_from)
        return {"key_id": kid, "key_class": key_class, "public_pem": public_pem,
                "private_path": str(private_path), "rotated_from": rotated_from}

    def keys(self) -> list[dict[str, Any]]:
        return self.store.keys()

    def key(self, key_id: str) -> dict[str, Any] | None:
        return self.store.key(key_id)

    def active(self, key_class: str) -> dict[str, Any] | None:
        for key in self.store.keys():
            if key["key_class"] == key_class and key["revoked_at"] is None:
                return key
        return None

    def sign(self, key_id: str, data: bytes) -> str:
        key = self.store.key(key_id)
        if key is None:
            raise TrustError("unknown key")
        if key["revoked_at"] is not None:
            raise TrustError("key revoked")
        return ed_sign(load_private(key["private_path"]), data)

    def verify(self, key_id: str, data: bytes, signature: str) -> bool:
        key = self.store.key(key_id)
        if key is None or key["revoked_at"] is not None:
            return False
        return ed_verify(public_from_pem(key["public_pem"]), data, signature)

    def revoke(self, key_id: str) -> None:
        self.store.revoke_key(key_id)

    def rotate(self, key_id: str) -> dict[str, Any]:
        old = self.store.key(key_id)
        if old is None:
            raise TrustError("unknown key")
        return self.create_key(old["key_class"], rotated_from=key_id)

    def propose(self, kind: str, target: str, payload: dict[str, Any],
                proposed_by: str) -> int:
        return self.store.propose_approval(kind, target, payload, proposed_by)

    def decide(self, approval_id: int, status: str, decided_by: str) -> None:
        self.store.decide_approval(approval_id, status, decided_by)

    def is_approved(self, kind: str, target: str) -> bool:
        return self.store.is_approved(kind, target)
