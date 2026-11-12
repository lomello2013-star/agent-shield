//! Immutable policy guards — Rust port of `core/policy.py`.
//!
//! The constants are normative and must never be changed without a human
//! `human_acceptance`. `verify_immutable` compares an observed snapshot against
//! the contract and returns `PolicyViolation` on any deviation.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use crate::sha256::sha256_hex;

pub const POLICY_VERSION: &str = "1";

// IMMUTABLE: requires human_acceptance.
pub const FAIL_SAFE_ON_TIMEOUT: &str = "reject";
pub const MODELS_TRAIN_ON_DEVICE: bool = false;
pub const DRIVER_SIGNED_BY_HUMAN: bool = true;
pub const KERNEL_CODE_REVIEW_REQUIRED: bool = true;

/// A policy value. Keeping the type closed prevents accidental JSON drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyValue {
    Bool(bool),
    Text(&'static str),
}

impl PolicyValue {
    fn json(self) -> String {
        match self {
            PolicyValue::Bool(true) => "true".to_string(),
            PolicyValue::Bool(false) => "false".to_string(),
            PolicyValue::Text(value) => {
                let mut out = String::with_capacity(value.len() + 2);
                out.push('"');
                // The contract only contains fixed ASCII identifiers/values; no
                // escaping is needed. Keep this in one place if a value changes.
                out.push_str(value);
                out.push('"');
                out
            }
        }
    }
}

/// The canonical immutable contract. `BTreeMap` gives the same key order as
/// Python `json.dumps(..., sort_keys=True)`.
pub fn immutable_constants() -> BTreeMap<&'static str, PolicyValue> {
    let mut values = BTreeMap::new();
    values.insert(
        "FAIL_SAFE_ON_TIMEOUT",
        PolicyValue::Text(FAIL_SAFE_ON_TIMEOUT),
    );
    values.insert(
        "MODELS_TRAIN_ON_DEVICE",
        PolicyValue::Bool(MODELS_TRAIN_ON_DEVICE),
    );
    values.insert(
        "DRIVER_SIGNED_BY_HUMAN",
        PolicyValue::Bool(DRIVER_SIGNED_BY_HUMAN),
    );
    values.insert(
        "KERNEL_CODE_REVIEW_REQUIRED",
        PolicyValue::Bool(KERNEL_CODE_REVIEW_REQUIRED),
    );
    values
}

/// Canonical JSON used for `POLICY_FINGERPRINT`.
///
/// Python: `json.dumps(IMMUTABLE_CONSTANTS, sort_keys=True, separators=(",", ":"))`.
pub fn canonical_json() -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in immutable_constants().iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(key);
        out.push_str("\":");
        out.push_str(&value.json());
    }
    out.push('}');
    out
}

/// SHA-256 of `canonical_json()`, computed once.
pub static POLICY_FINGERPRINT: LazyLock<String> =
    LazyLock::new(|| sha256_hex(canonical_json().as_bytes()));

/// A copy of the immutable policy values.
pub fn snapshot() -> BTreeMap<&'static str, PolicyValue> {
    immutable_constants()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyViolation(pub String);

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyViolation {}

/// Verify that `values` still match the contract.
///
/// `None` verifies the live constants; `Some(map)` verifies an observed
/// snapshot (used by the daemon and tests).
pub fn verify_immutable(
    values: Option<&BTreeMap<&'static str, PolicyValue>>,
) -> Result<(), PolicyViolation> {
    let contract = immutable_constants();
    let observed = values.cloned().unwrap_or_else(|| contract.clone());

    let missing: Vec<&'static str> = contract
        .keys()
        .filter(|key| !observed.contains_key(*key))
        .copied()
        .collect();

    let mut changed: BTreeMap<&'static str, PolicyValue> = BTreeMap::new();
    for (key, expected) in &contract {
        if let Some(actual) = observed.get(key) {
            if actual != expected {
                changed.insert(*key, *actual);
            }
        }
    }

    if missing.is_empty() && changed.is_empty() {
        Ok(())
    } else {
        Err(PolicyViolation(format!(
            "immutable policy changed (missing={missing:?}, changed={changed:?}); \
             human_acceptance required"
        )))
    }
}

/// Decision used when a confirmation times out (fail-safe, R9).
pub fn fail_safe_decision() -> &'static str {
    FAIL_SAFE_ON_TIMEOUT
}
