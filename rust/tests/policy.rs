use aidf_core::policy::{
    canonical_json, fail_safe_decision, immutable_constants, snapshot, verify_immutable,
    PolicyValue, DRIVER_SIGNED_BY_HUMAN, FAIL_SAFE_ON_TIMEOUT, KERNEL_CODE_REVIEW_REQUIRED,
    MODELS_TRAIN_ON_DEVICE, POLICY_FINGERPRINT, POLICY_VERSION,
};

const PYTHON_FINGERPRINT: &str = "d8ae913401ead8b0d549dbae9d0efb299020b24e49b87a9385ab7071446ea759";

#[test]
fn immutable_values_match_python_contract() {
    assert_eq!(POLICY_VERSION, "1");
    assert_eq!(FAIL_SAFE_ON_TIMEOUT, "reject");
    const { assert!(!MODELS_TRAIN_ON_DEVICE) };
    const { assert!(DRIVER_SIGNED_BY_HUMAN) };
    const { assert!(KERNEL_CODE_REVIEW_REQUIRED) };
}

#[test]
fn canonical_json_matches_python_json_dumps() {
    assert_eq!(
        canonical_json(),
        "{\"DRIVER_SIGNED_BY_HUMAN\":true,\"FAIL_SAFE_ON_TIMEOUT\":\"reject\",\
         \"KERNEL_CODE_REVIEW_REQUIRED\":true,\"MODELS_TRAIN_ON_DEVICE\":false}"
    );
}

#[test]
fn fingerprint_matches_python_artifact() {
    assert_eq!(POLICY_FINGERPRINT.as_str(), PYTHON_FINGERPRINT);
}

#[test]
fn snapshot_is_a_copy() {
    let mut snap = snapshot();
    snap.insert("MODELS_TRAIN_ON_DEVICE", PolicyValue::Bool(true));
    assert_eq!(
        immutable_constants().get("MODELS_TRAIN_ON_DEVICE"),
        Some(&PolicyValue::Bool(false))
    );
}

#[test]
fn verify_contract_accepts_live_and_snapshot() {
    verify_immutable(None).expect("live contract must verify");
    verify_immutable(Some(&snapshot())).expect("snapshot must verify");
}

#[test]
fn verify_rejects_tampering() {
    let mut bad = snapshot();
    bad.insert("MODELS_TRAIN_ON_DEVICE", PolicyValue::Bool(true));
    let error = verify_immutable(Some(&bad)).expect_err("tampering must be rejected");
    assert!(error.to_string().contains("human_acceptance required"));
}

#[test]
fn verify_rejects_missing_key() {
    let mut bad = snapshot();
    bad.remove("FAIL_SAFE_ON_TIMEOUT");
    assert!(verify_immutable(Some(&bad)).is_err());
}

#[test]
fn fail_safe_is_reject() {
    assert_eq!(fail_safe_decision(), "reject");
}
