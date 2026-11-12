"""F07: signing keys must never live inside artifacts/ (and never be committed)."""

import json
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
SECRETS = ROOT / "secrets"


def test_no_dev_keys_in_artifacts():
    assert not (ART / "dev_keys.json").exists(), (
        "dev_keys.json must live in secrets/, not in artifacts/")
    for path in ART.glob("*.json"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        assert '"private_hex"' not in text, f"{path.name} contains a private key"


def test_dev_keys_are_outside_the_repository_artifacts():
    key_file = SECRETS / "dev_keys.json"
    if not key_file.exists():
        return                                  # CI may not provision dev keys at all
    payload = json.loads(key_file.read_text(encoding="utf-8"))
    assert payload["note"].startswith("DEV ONLY")
    assert len(payload["private_hex"]) == 64
    assert len(payload["public_hex"]) == 64


def test_artifacts_loader_hides_secrets():
    """The status document must not advertise the key file even if it reappears."""
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    import status_text
    rendered = status_text.render([], {"dev_keys.json": {}}, __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc), str(ART))
    assert "dev_keys.json" not in rendered
