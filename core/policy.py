"""Immutable policy guards — roadmap v9.1 §10.6.

IMMUTABLE: `requires human_acceptance`. CI must block a merge that touches these
values unless a human-signed commit from the allowlist is attached (see
docs/auto-reviewer-spec.md §4.2). The agent must never change them.

The normative reference lives in the tracked, human-reviewed
``docs/policy-contract.json``. ``verify_immutable()`` compares the live module
globals against that contract (and its fingerprint), so editing this file alone
cannot silently pass the check.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

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

CONTRACT_PATH = Path(__file__).resolve().parent.parent / "docs" / "policy-contract.json"


class PolicyViolation(RuntimeError):
    """Raised when an immutable policy value deviates from the normative contract."""


def snapshot() -> dict[str, object]:
    """Return a copy of the immutable policy values."""
    return dict(IMMUTABLE_CONSTANTS)


def load_contract() -> dict:
    """Load the tracked policy contract (external, human-reviewed reference)."""
    if not CONTRACT_PATH.exists():
        raise PolicyViolation(f"policy contract missing: {CONTRACT_PATH}")
    try:
        data = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyViolation(f"policy contract unreadable: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("constants"), dict):
        raise PolicyViolation("policy contract malformed: 'constants' object required")
    return data


def verify_immutable(values: dict[str, object] | None = None,
                     contract: dict | None = None) -> None:
    """Verify policy values against the tracked contract.

    Args:
        values: mapping to check; defaults to the live module globals.
        contract: contract mapping; defaults to ``docs/policy-contract.json``.

    With no arguments this compares the live globals to the external contract and
    its fingerprint, so editing this module alone is detected (no tautology).

    Raises:
        PolicyViolation: on a missing key, a changed value, or fingerprint drift.
    """
    c = contract if contract is not None else load_contract()
    expected = c["constants"]
    observed = snapshot() if values is None else dict(values)
    problems: list[str] = []
    missing = sorted(set(expected) - set(observed))
    changed = {k: observed[k] for k in expected
               if k in observed and observed[k] != expected[k]}
    if missing:
        problems.append(f"missing={missing}")
    if changed:
        problems.append(f"changed={changed}")
    if values is None:
        fingerprint = c.get("fingerprint")
        if not fingerprint or fingerprint != POLICY_FINGERPRINT:
            problems.append("fingerprint drifted from contract")
    if problems:
        raise PolicyViolation(
            f"immutable policy changed ({', '.join(problems)}); "
            "human_acceptance required"
        )


def fail_safe_decision() -> str:
    """Decision used when a confirmation times out (fail-safe, R9)."""
    return str(FAIL_SAFE_ON_TIMEOUT)
