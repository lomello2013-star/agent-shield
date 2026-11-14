import json

from stml.connector.release import build_manifest, sign_manifest, verify_manifest
from stml.connector.signing import generate_keypair, key_id, load_private, load_public, sign, verify


def test_ed25519_roundtrip_and_tamper(tmp_path):
    priv = tmp_path / "key.pem"
    pub = tmp_path / "key.pub"
    kid = generate_keypair(priv, pub)
    assert kid == key_id(load_public(pub))
    signature = sign(load_private(priv), b"hello")
    assert verify(load_public(pub), b"hello", signature)
    assert not verify(load_public(pub), b"tampered", signature)


def test_signed_package_manifest(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "a.py").write_text("print('a')\n", encoding="utf-8")
    (root / "b.txt").write_text("b\n", encoding="utf-8")
    priv, pub = tmp_path / "key.pem", tmp_path / "key.pub"
    generate_keypair(priv, pub)
    manifest = sign_manifest(build_manifest(root, "0.1.0"), load_private(priv))
    assert verify_manifest(manifest, load_public(pub), root) == []
    (root / "a.py").write_text("print('changed')\n", encoding="utf-8")
    assert any("hash mismatch" in e for e in verify_manifest(manifest, load_public(pub), root))


def test_manifest_rejects_wrong_key(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "a.py").write_text("a\n", encoding="utf-8")
    priv, pub = tmp_path / "key.pem", tmp_path / "key.pub"
    other_priv, other_pub = tmp_path / "other.pem", tmp_path / "other.pub"
    generate_keypair(priv, pub)
    generate_keypair(other_priv, other_pub)
    manifest = sign_manifest(build_manifest(root, "0.1.0"), load_private(priv))
    errors = verify_manifest(manifest, load_public(other_pub))
    assert "key_id mismatch" in errors
    assert "bad signature" in errors
