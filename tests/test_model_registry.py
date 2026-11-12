import hashlib
import json

import pytest

from core.model_registry import ModelEntry, ModelRegistry, RegistryError
from core.modelpack import (generate_dev_keypair, load_public_key, private_key_from_hex,
                            sign_pack)

PRIV, PUB = generate_dev_keypair()


def make_artifact(tmp_path, name="m.onnx", content=b"onnx-bytes"):
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


def make_pack(tmp_path, artifact, model_id="m", version="1.0.0", content=None):
    data = open(artifact, "rb").read()
    pack = {"model_id": model_id, "version": version, "platform": "windows",
            "format": "onnx", "sha256": hashlib.sha256(data).hexdigest(),
            "dataset_hash": "d" * 64, "metrics": {"tpr": 0.9}, "limits": {}}
    pack["signature"] = sign_pack(pack, private_key_from_hex(PRIV))
    path = tmp_path / f"{model_id}-{version}-pack.json"
    path.write_text(json.dumps(pack), encoding="utf-8")
    return str(path)


def entry(tmp_path, model_id="m", version="1.0.0", role="challenger"):
    art = make_artifact(tmp_path, name=f"{model_id}-{version}.onnx")
    pack = make_pack(tmp_path, art, model_id, version)
    return ModelEntry(model_id=model_id, version=version, role=role,
                      artifact=art, pack_path=pack, metrics={"tpr": 0.9})


def registry(tmp_path):
    return ModelRegistry(str(tmp_path / "models"), PUB)


def test_register_and_persist(tmp_path):
    reg = registry(tmp_path)
    reg.register(entry(tmp_path))
    again = registry(tmp_path)
    assert len(again.entries) == 1 and again.entries[0].model_id == "m"


def test_register_rejects_unsigned_pack(tmp_path):
    reg = registry(tmp_path)
    art = make_artifact(tmp_path)
    pack = make_pack(tmp_path, art)
    payload = json.load(open(pack, encoding="utf-8"))
    payload["signature"] = ""
    bad = tmp_path / "bad-pack.json"
    bad.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RegistryError):
        reg.register(ModelEntry("m", "1.0.0", "challenger", art, str(bad)))


def test_register_rejects_tampered_artifact(tmp_path):
    reg = registry(tmp_path)
    e = entry(tmp_path)
    with open(e.artifact, "wb") as fh:
        fh.write(b"tampered")
    with pytest.raises(RegistryError):
        reg.register(e)


def test_promotion_to_champion_requires_human(tmp_path):
    reg = registry(tmp_path)
    reg.register(entry(tmp_path))
    with pytest.raises(RegistryError):
        reg.promote("m", "1.0.0", "champion", operator=False)
    promoted = reg.promote("m", "1.0.0", "champion", operator=True)
    assert promoted.role == "champion" and reg.champion().model_id == "m"


def test_promoting_new_champion_retires_previous(tmp_path):
    reg = registry(tmp_path)
    reg.register(entry(tmp_path, "a", "1.0.0", role="champion"))
    reg.register(entry(tmp_path, "b", "2.0.0", role="challenger"))
    reg.promote("b", "2.0.0", "champion", operator=True)
    roles = {e.model_id: e.role for e in reg.entries}
    assert roles == {"a": "retired", "b": "champion"}


def test_single_champion_enforced_on_register(tmp_path):
    reg = registry(tmp_path)
    reg.register(entry(tmp_path, "a", "1.0.0", role="champion"))
    with pytest.raises(RegistryError):
        reg.register(entry(tmp_path, "b", "1.0.0", role="champion"))


def test_duplicate_registration_rejected(tmp_path):
    reg = registry(tmp_path)
    e = entry(tmp_path)
    reg.register(e)
    with pytest.raises(RegistryError):
        reg.register(e)


def test_retire_requires_human(tmp_path):
    reg = registry(tmp_path)
    reg.register(entry(tmp_path))
    with pytest.raises(RegistryError):
        reg.retire("m", "1.0.0", operator=False)
    assert reg.retire("m", "1.0.0", operator=True).role == "retired"


def test_unknown_model_raises(tmp_path):
    reg = registry(tmp_path)
    with pytest.raises(RegistryError):
        reg.promote("ghost", "9.9.9", "challenger", operator=True)


def test_bad_role_rejected(tmp_path):
    with pytest.raises(RegistryError):
        ModelEntry("m", "1.0.0", "king", "a", "p")
