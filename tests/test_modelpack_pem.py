import base64
import hashlib

from core.modelpack import (
    generate_dev_keypair,
    private_key_from_hex,
    private_key_from_pem,
    private_key_to_pem,
    public_key_from_pem,
    public_key_hex_from_pem,
    public_key_pem_from_hex,
    sign_pack,
    verify_pack,
    verify_pack_pem,
)


def _pack(tmp_path):
    artifact = tmp_path / "model.onnx"
    artifact.write_bytes(b"model-bytes")
    priv_hex, pub_hex = generate_dev_keypair()
    pack = {"model_id": "m1", "version": "1", "platform": "windows",
            "format": "onnx", "sha256": hashlib.sha256(b"model-bytes").hexdigest(),
            "dataset_hash": "a" * 64, "metrics": {"tpr": 0.9}, "limits": {}}
    pack["signature"] = sign_pack(pack, private_key_from_hex(priv_hex))
    return pack, artifact, priv_hex, pub_hex


def test_modelpack_hex_and_pem_verify(tmp_path):
    pack, artifact, _priv, pub_hex = _pack(tmp_path)
    assert verify_pack(pack, str(artifact), public_key_from_pem(public_key_pem_from_hex(pub_hex))).ok
    assert verify_pack_pem(pack, str(artifact), public_key_pem_from_hex(pub_hex)).ok
    assert public_key_hex_from_pem(public_key_pem_from_hex(pub_hex)) == pub_hex


def test_modelpack_base64_signature_and_tamper(tmp_path):
    pack, artifact, _priv, pub_hex = _pack(tmp_path)
    pack["signature"] = base64.b64encode(bytes.fromhex(pack["signature"])).decode()
    assert verify_pack(pack, str(artifact),
                       public_key_from_pem(public_key_pem_from_hex(pub_hex))).ok
    pack["version"] = "2"
    result = verify_pack(pack, str(artifact),
                         public_key_from_pem(public_key_pem_from_hex(pub_hex)))
    assert result.ok is False and result.code == "signature_invalid"


def test_private_key_pem_roundtrip():
    priv_hex, _ = generate_dev_keypair()
    key = private_key_from_hex(priv_hex)
    again = private_key_from_pem(private_key_to_pem(key))
    assert again.private_bytes_raw() == key.private_bytes_raw()
