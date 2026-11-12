"""Immutable policy guards — roadmap v9.1 §10.6.

IMMUTABLE: `requires human_acceptance`. CI must block a merge that touches these
values unless a human-signed commit from the allowlist is attached (see
docs/auto-reviewer-spec.md §4.2). The agent must never change them.

The values below are the normative contract; `verify_immutable()` compares a
snapshot against them and raises `PolicyViolation` on any deviation.
"""

from __future__ import annotations

import hashlib
import json

POLICY_VERSION = "1"

# IMMUTABLE: requires human_acceptance
FAIL_SAFE_ON_TIMEOUT = "reject"        # НИКОГДА не "accept"
MODELS_TRAIN_ON_DEVICE = False         # НИКОГДА не True
DRIVER_SIGNED_BY_HUMAN = True          # НИКОГДА не False
KERNEL_CODE_REVIEW_REQUIRED = True     # НИКОГДА не False

IMMUTABLE_CONSTANTS: dict[str, object] = {
    "FAIL_SAFE_ON_TIMEOUT": FAIL_SAFE_ON_TIMEOUT,
    "MODELS_TRAIN_ON_DEVICE": MODELS_TRAIN_ON_DEVICE,
    "DRIVER_SIGNED_BY_HUMAN": DRIVER_SIGNED_BY_HUMAN,
    "KERNEL_CODE_REVIEW_REQUIRED": KERNEL_CODE_REVIEW_REQUIRED,
}

POLICY_FINGERPRINT = hashlib.sha256(
    json.dumps(IMMUTABLE_CONSTANTS, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


class PolicyViolation(RuntimeError):
    """Raised when an immutable policy value deviates from the normative contract."""


def snapshot() -> dict[str, object]:
    """Return a copy of the immutable policy values."""
    return dict(IMMUTABLE_CONSTANTS)


def verify_immutable(values: dict[str, object] | None = None) -> None:
    """Verify that policy values still match the contract.

    Args:
        values: mapping to check; defaults to the live module globals.

    Raises:
        PolicyViolation: if a key is missing or has a different value.
    """
    observed = snapshot() if values is None else dict(values)
    missing = sorted(set(IMMUTABLE_CONSTANTS) - set(observed))
    extra_changed = {k: observed[k] for k in IMMUTABLE_CONSTANTS
                     if k in observed and observed[k] != IMMUTABLE_CONSTANTS[k]}
    if missing or extra_changed:
        raise PolicyViolation(
            f"immutable policy changed (missing={missing}, changed={extra_changed}); "
            "human_acceptance required"
        )


def fail_safe_decision() -> str:
    """Decision used when a confirmation times out (fail-safe, R9)."""
    return str(FAIL_SAFE_ON_TIMEOUT)
