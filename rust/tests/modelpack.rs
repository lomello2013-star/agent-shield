use std::path::{Path, PathBuf};

use aidf_core::modelpack::{
    canonical_payload, generate_dev_keypair, load_public_key, private_key_from_hex, sha256_file,
    sign_pack, verify_pack,
};
use serde_json::{json, Value};

fn temp_file(name: &str, content: &[u8]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp");
    let _ = std::fs::create_dir_all(&root);
    let path = root.join(format!("aidf-pack-{}-{name}", uuid::Uuid::new_v4()));
    std::fs::write(&path, content).unwrap();
    path
}

fn fields(content: &[u8]) -> Value {
    json!({
        "model_id": "pe-ember",
        "version": "1.0.0",
        "platform": "windows",
        "format": "onnx",
        "sha256": sha256_file_bytes(content),
        "dataset_hash": "1".repeat(64),
        "metrics": {"tpr_at_fpr_1pct": 0.85},
        "limits": {"max_mb": 200}
    })
}

fn sha256_file_bytes(content: &[u8]) -> String {
    // Reuse the public file helper to avoid duplicating the hash in the test.
    let path = temp_file("hash", content);
    let digest = sha256_file(path.to_str().unwrap());
    let _ = std::fs::remove_file(path);
    digest
}

fn make_pack(content: &[u8]) -> (Value, PathBuf, String) {
    let artifact = temp_file("model.onnx", content);
    let mut pack = fields(content);
    let (private_hex, public_hex) = generate_dev_keypair();
    let signing_key = private_key_from_hex(&private_hex).unwrap();
    pack["signature"] = json!(sign_pack(&pack, &signing_key));
    (pack, artifact, public_hex)
}

#[test]
fn signed_pack_verifies() {
    let (pack, artifact, public_hex) = make_pack(b"onnx-bytes");
    let result = verify_pack(
        &pack,
        artifact.to_str().unwrap(),
        Some(&load_public_key(&public_hex).unwrap()),
    );
    assert!(result.ok);
    assert_eq!(result.code, "ok");
}

#[test]
fn tampered_artifact_detected() {
    let (pack, artifact, public_hex) = make_pack(b"onnx-bytes");
    std::fs::write(&artifact, b"evil").unwrap();
    let result = verify_pack(
        &pack,
        artifact.to_str().unwrap(),
        Some(&load_public_key(&public_hex).unwrap()),
    );
    assert!(!result.ok);
    assert_eq!(result.code, "hash_mismatch");
}

#[test]
fn tampered_manifest_breaks_signature() {
    let (mut pack, artifact, public_hex) = make_pack(b"onnx-bytes");
    pack["version"] = json!("9.9.9");
    let result = verify_pack(
        &pack,
        artifact.to_str().unwrap(),
        Some(&load_public_key(&public_hex).unwrap()),
    );
    assert!(!result.ok);
    assert_eq!(result.code, "signature_invalid");
}

#[test]
fn unsigned_pack_rejected() {
    let (mut pack, artifact, public_hex) = make_pack(b"onnx-bytes");
    pack["signature"] = json!("");
    let result = verify_pack(
        &pack,
        artifact.to_str().unwrap(),
        Some(&load_public_key(&public_hex).unwrap()),
    );
    assert!(!result.ok);
    assert_eq!(result.code, "invalid_manifest");
}

#[test]
fn wrong_key_rejected() {
    let (pack, artifact, _) = make_pack(b"onnx-bytes");
    let (_, other_public) = generate_dev_keypair();
    let result = verify_pack(
        &pack,
        artifact.to_str().unwrap(),
        Some(&load_public_key(&other_public).unwrap()),
    );
    assert!(!result.ok);
    assert_eq!(result.code, "signature_invalid");
}

#[test]
fn missing_artifact_rejected() {
    let (pack, _, public_hex) = make_pack(b"onnx-bytes");
    let missing = Path::new("target").join("definitely-not-here.onnx");
    let result = verify_pack(
        &pack,
        missing.to_str().unwrap(),
        Some(&load_public_key(&public_hex).unwrap()),
    );
    assert!(!result.ok);
    assert_eq!(result.code, "missing_artifact");
}

#[test]
fn no_trusted_key_rejected() {
    let (pack, artifact, _) = make_pack(b"onnx-bytes");
    let result = verify_pack(&pack, artifact.to_str().unwrap(), None);
    assert!(!result.ok);
    assert_eq!(result.code, "untrusted_key");
}

#[test]
fn invalid_manifest_rejected() {
    let (mut pack, artifact, public_hex) = make_pack(b"onnx-bytes");
    pack["sha256"] = json!("not-a-hash");
    let result = verify_pack(
        &pack,
        artifact.to_str().unwrap(),
        Some(&load_public_key(&public_hex).unwrap()),
    );
    assert!(!result.ok);
    assert_eq!(result.code, "invalid_manifest");
}

#[test]
fn canonical_payload_is_stable_and_excludes_signature() {
    let (pack, _, _) = make_pack(b"onnx-bytes");
    let a = canonical_payload(&pack);
    let mut reversed = serde_json::Map::new();
    for (key, value) in pack.as_object().unwrap().iter().rev() {
        reversed.insert(key.clone(), value.clone());
    }
    let b = canonical_payload(&Value::Object(reversed));
    assert_eq!(a, b);
    assert!(!String::from_utf8_lossy(&a).contains("signature"));
    let parsed: Value = serde_json::from_slice(&a).unwrap();
    assert_eq!(parsed["model_id"], "pe-ember");
}

#[test]
fn sha256_file_matches_known_vector() {
    let path = temp_file("abc.bin", b"abc");
    assert_eq!(
        sha256_file(path.to_str().unwrap()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
