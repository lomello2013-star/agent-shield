import pathlib
import re

import pytest

from core import policy


def test_immutable_values_match_roadmap():
    assert policy.FAIL_SAFE_ON_TIMEOUT == "reject"
    assert policy.MODELS_TRAIN_ON_DEVICE is False
    assert policy.DRIVER_SIGNED_BY_HUMAN is True
    assert policy.KERNEL_CODE_REVIEW_REQUIRED is True


def test_snapshot_is_a_copy():
    snap = policy.snapshot()
    snap["MODELS_TRAIN_ON_DEVICE"] = True
    assert policy.MODELS_TRAIN_ON_DEVICE is False


def test_verify_immutable_accepts_contract():
    policy.verify_immutable()  # must not raise
    policy.verify_immutable(policy.snapshot())


def test_verify_immutable_rejects_tampering():
    bad = policy.snapshot()
    bad["MODELS_TRAIN_ON_DEVICE"] = True
    with pytest.raises(policy.PolicyViolation):
        policy.verify_immutable(bad)


def test_verify_immutable_rejects_missing_key():
    bad = policy.snapshot()
    del bad["FAIL_SAFE_ON_TIMEOUT"]
    with pytest.raises(policy.PolicyViolation):
        policy.verify_immutable(bad)


def test_failure_decision_is_reject():
    assert policy.fail_safe_decision() == "reject"


def test_fingerprint_is_stable_and_hex():
    assert re.fullmatch(r"[0-9a-f]{64}", policy.POLICY_FINGERPRINT)
    assert policy.POLICY_FINGERPRINT == policy.POLICY_FINGERPRINT


def test_no_training_calls_in_runtime_core():
    """MODELS_TRAIN_ON_DEVICE=False: runtime must never call fit/train."""
    banned = re.compile(r"\.(fit|fit_transform|partial_fit|train)\s*\(")
    offenders = []
    for path in pathlib.Path("core").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if banned.search(text):
            offenders.append(path.name)
    assert offenders == [], f"training calls found in runtime modules: {offenders}"
