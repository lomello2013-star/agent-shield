"""Signed A/B bundles: manifest, signature, staging, health rollback."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.update_package import (
    apply_bundle,
    bundle_from_file,
    bundle_to_file,
    sign_bundle,
    verify_bundle,
)
from core.updater import DualSlot, UpdateError


def _keys(tmp_path):
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub


def test_sign_verify_roundtrip(tmp_path):
    priv, pub = _keys(tmp_path)
    bundle = sign_bundle("1.2.0", {"bin/aidfd": b"v2", "rules/base.json": b"{}"}, priv)
    files = verify_bundle(bundle, pub)
    assert files["bin/aidfd"] == b"v2"
    assert files["rules/base.json"] == b"{}"


def test_tampered_file_is_rejected(tmp_path):
    priv, pub = _keys(tmp_path)
    bundle = sign_bundle("1.2.0", {"f": b"v2"}, priv)
    bundle["files"]["f"] = base64.b64encode(b"evil").decode()
    with pytest.raises(UpdateError):
        verify_bundle(bundle, pub)


def test_tampered_manifest_is_rejected(tmp_path):
    priv, pub = _keys(tmp_path)
    bundle = sign_bundle("1.2.0", {"f": b"v2"}, priv)
    bundle["manifest"]["version"] = "9.9.9"
    with pytest.raises(UpdateError):
        verify_bundle(bundle, pub)


def test_apply_and_rollback(tmp_path):
    priv, pub = _keys(tmp_path)
    slots = tmp_path / "slots"
    bundle = sign_bundle("1.2.0", {"f": b"new"}, priv)
    res = apply_bundle(str(slots), bundle, pub)
    assert res["result"] == "updated" and res["version"] == "1.2.0"
    ds = DualSlot(str(slots))
    assert ds.active_slot() == "B"
    rolled = ds.rollback()
    assert rolled["slot"] == "A"
    assert rolled["version"] == "0.0.0"


def test_health_regression_rolls_back(tmp_path):
    priv, pub = _keys(tmp_path)
    bundle = sign_bundle("1.3.0", {"f": b"new"}, priv)
    res = apply_bundle(str(tmp_path / "slots"), bundle, pub, health=lambda: False)
    assert res["result"] == "rolled_back"
    assert DualSlot(str(tmp_path / "slots")).active_slot() == "A"


def test_bundle_file_roundtrip(tmp_path):
    priv, pub = _keys(tmp_path)
    bundle = sign_bundle("1.0.1", {"x": b"1"}, priv)
    path = tmp_path / "b.json"
    bundle_to_file(bundle, path)
    assert bundle_from_file(path)["version"] == "1.0.1"
    assert verify_bundle(bundle_from_file(path), pub)["x"] == b"1"
