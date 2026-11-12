import hashlib
import json

import pytest

from core.modelpack import (
    canonical_payload,
    generate_dev_keypair,
    load_public_key,
    private_key_from_hex,
    sha256_file,
    sign_pack,
    verify_pack,
)

FIELDS = {
    "model_id": "pe-ember", "version": "1.0.0", "platform": "windows", "format": "onnx",
    "sha256": "0" * 64, "dataset_hash": "1" * 64,
    "metrics": {"tpr_at_fpr_1pct": 0.85}, "limits": {"max_mb": 200},
}


def make_pack(tmp_path, content=b"onnx-bytes"):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(content)
    pack = dict(FIELDS, sha256=hashlib.sha256(content).hexdigest())
    priv_hex, pub_hex = generate_dev_keypair()
    pack["signature"] = sign_pack(pack, private_key_from_hex(priv_hex))
    return pack, str(artifact), pub_hex, priv_hex


def test_signed_pack_verifies(tmp_path):
    pack, artifact, pub_hex, _ = make_pack(tmp_path)
    result = verify_pack(pack, artifact, load_public_key(pub_hex))
    assert result.ok and result.code == "ok"


def test_tampered_artifact_detected(tmp_path):
    pack, artifact, pub_hex, _ = make_pack(tmp_path)
    with open(artifact, "wb") as fh:
        fh.write(b"evil")
    result = verify_pack(pack, artifact, load_public_key(pub_hex))
    assert not result.ok and result.code == "hash_mismatch"


def test_tampered_manifest_breaks_signature(tmp_path):
    pack, artifact, pub_hex, _ = make_pack(tmp_path)
    pack["version"] = "9.9.9"
    result = verify_pack(pack, artifact, load_public_key(pub_hex))
    assert not result.ok and result.code == "signature_invalid"


def test_unsigned_pack_rejected(tmp_path):
    pack, artifact, pub_hex, _ = make_pack(tmp_path)
    pack["signature"] = ""
    result = verify_pack(pack, artifact, load_public_key(pub_hex))
    assert not result.ok and result.code == "invalid_manifest"


def test_wrong_key_rejected(tmp_path):
    pack, artifact, _, _ = make_pack(tmp_path)
    _, other_pub = generate_dev_keypair()
    result = verify_pack(pack, artifact, load_public_key(other_pub))
    assert not result.ok and result.code == "signature_invalid"


def test_missing_artifact_rejected(tmp_path):
    pack, artifact, pub_hex, _ = make_pack(tmp_path)
    result = verify_pack(pack, str(tmp_path / "nope.onnx"), load_public_key(pub_hex))
    assert not result.ok and result.code == "missing_artifact"


def test_no_trusted_key_rejected(tmp_path):
    pack, artifact, _, _ = make_pack(tmp_path)
    result = verify_pack(pack, artifact, None)
    assert not result.ok and result.code == "untrusted_key"


def test_invalid_manifest_rejected(tmp_path):
    pack, artifact, pub_hex, _ = make_pack(tmp_path)
    pack["sha256"] = "not-a-hash"
    result = verify_pack(pack, artifact, load_public_key(pub_hex))
    assert not result.ok and result.code == "invalid_manifest"


def test_canonical_payload_is_stable_and_excludes_signature(tmp_path):
    pack, _, _, _ = make_pack(tmp_path)
    a = canonical_payload(pack)
    b = canonical_payload(dict(reversed(list(pack.items()))))
    assert a == b
    assert b"signature" not in a
    assert json.loads(a)["model_id"] == "pe-ember"


def test_sha256_file_matches_hashlib(tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"abc")
    assert sha256_file(str(path)) == hashlib.sha256(b"abc").hexdigest()
