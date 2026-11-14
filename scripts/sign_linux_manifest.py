#!/usr/bin/env python3
"""Sign the Linux object manifest with the lab Ed25519 key (DEV ONLY)."""
from __future__ import annotations

import json
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    manifest = pathlib.Path("packaging/linux/objects.sha256")
    key = json.loads((root / "secrets" / "dev_keys.json").read_text(encoding="utf-8"))
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["private_hex"]))
    signature = private.sign(manifest.read_bytes())
    manifest.with_suffix(".sha256.sig").write_bytes(signature)
    public = private.public_key().public_bytes_raw().hex()
    manifest.with_suffix(".sha256.pub").write_text(public + "\n", encoding="utf-8")
    print(f"signed {manifest} -> {manifest.name}.sig; pub={public[:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
