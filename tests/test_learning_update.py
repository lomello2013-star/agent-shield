import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from core.daemon import Daemon
from core.learning_update import canonical_update


def _update():
    private = Ed25519PrivateKey.generate()
    pub = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    update = {"update_id": "11111111-1111-1111-1111-111111111111",
              "version": "1", "rules": [], "model_packs": [],
              "qa_pairs": [], "task_solutions": [], "kb_version": "1"}
    update["signature"] = base64.b64encode(private.sign(canonical_update(update))).decode()
    return update, pub, private


def test_learning_update_verify_and_store(tmp_path):
    daemon = Daemon(str(tmp_path), collectors=[])
    update, pub, _ = _update()
    result = daemon.execute_command("learning_update", {"update": update, "pubkey": pub})
    assert result["status"] == "acked"
    assert result["stored"] == 1
    stored = json.loads((tmp_path / "learning_updates.json").read_text())
    assert stored[0]["update_id"] == update["update_id"]


def test_learning_update_bad_signature(tmp_path):
    daemon = Daemon(str(tmp_path), collectors=[])
    update, pub, _ = _update()
    update["version"] = "2"
    result = daemon.execute_command("learning_update", {"update": update, "pubkey": pub})
    assert result["status"] == "failed"
    assert not (tmp_path / "learning_updates.json").exists()
