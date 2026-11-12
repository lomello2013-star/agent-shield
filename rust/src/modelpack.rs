//! Signed ModelPack verification — Rust port of `core/modelpack.py`.
//!
//! A model is loaded only if the manifest validates, the artifact hash matches,
//! and the Ed25519 signature over the canonical manifest verifies. Any failure is
//! a hard rejection (fail-closed) with a machine-readable code.

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde_json::{Map, Value};

use crate::sha256::sha256_hex;

pub const SIGNED_FIELDS: [&str; 8] = [
    "model_id",
    "version",
    "platform",
    "format",
    "sha256",
    "dataset_hash",
    "metrics",
    "limits",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationResult {
    pub ok: bool,
    pub code: String,
    pub detail: String,
}

impl VerificationResult {
    fn new(ok: bool, code: &str, detail: impl Into<String>) -> Self {
        Self {
            ok,
            code: code.to_owned(),
            detail: detail.into(),
        }
    }
}

/// Canonical bytes covered by the signature (stable ordering, no signature field).
pub fn canonical_payload(pack: &Value) -> Vec<u8> {
    let mut body: BTreeMap<&str, Value> = BTreeMap::new();
    for field in SIGNED_FIELDS {
        if let Some(value) = pack.get(field) {
            body.insert(field, value.clone());
        }
    }
    serde_json::to_vec(&body).unwrap_or_default()
}

pub fn sha256_file(path: &str) -> String {
    match std::fs::read(path) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(_) => String::new(),
    }
}

pub fn sign_pack(pack: &Value, private_key: &SigningKey) -> String {
    let signature = private_key.sign(&canonical_payload(pack));
    hex_encode(&signature.to_bytes())
}

/// Verify a pack; the Python contract returns a `VerificationResult` rather than
/// throwing, so the daemon can log a stable code.
pub fn verify_pack(
    pack: &Value,
    artifact_path: &str,
    public_key: Option<&VerifyingKey>,
) -> VerificationResult {
    let Some(manifest) = pack.as_object() else {
        return VerificationResult::new(false, "invalid_manifest", "pack must be an object");
    };
    if let Err(detail) = validate_manifest(manifest) {
        return VerificationResult::new(false, "invalid_manifest", detail);
    }
    let format = manifest
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if format != "onnx" && format != "gguf" {
        return VerificationResult::new(false, "unsupported_format", format);
    }
    let Some(public_key) = public_key else {
        return VerificationResult::new(false, "untrusted_key", "no trusted public key configured");
    };
    if !Path::new(artifact_path).exists() {
        return VerificationResult::new(false, "missing_artifact", artifact_path);
    }
    let actual = sha256_file(artifact_path);
    let expected = manifest
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_lowercase();
    if actual != expected {
        return VerificationResult::new(false, "hash_mismatch", format!("{actual} != {expected}"));
    }
    let signature_hex = manifest
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(signature_bytes) = decode_hex(signature_hex) else {
        return VerificationResult::new(false, "invalid_manifest", "signature is not hex");
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return VerificationResult::new(false, "invalid_manifest", "signature must be 64 bytes");
    };
    if public_key
        .verify_strict(&canonical_payload(pack), &signature)
        .is_err()
    {
        return VerificationResult::new(false, "signature_invalid", "Ed25519 verification failed");
    }
    VerificationResult::new(true, "ok", "")
}

fn validate_manifest(manifest: &Map<String, Value>) -> Result<(), String> {
    const KNOWN: [&str; 9] = [
        "model_id",
        "version",
        "platform",
        "format",
        "sha256",
        "dataset_hash",
        "metrics",
        "limits",
        "signature",
    ];
    if let Some(extra) = manifest.keys().find(|key| !KNOWN.contains(&key.as_str())) {
        return Err(format!("extra field: {extra}"));
    }
    for field in [
        "model_id",
        "version",
        "platform",
        "format",
        "sha256",
        "dataset_hash",
    ] {
        match manifest.get(field).and_then(Value::as_str) {
            Some(value) if !value.is_empty() => {}
            _ => return Err(format!("{field} must be a non-empty string")),
        }
    }
    let platform = manifest["platform"].as_str().unwrap_or_default();
    if platform != "windows" && platform != "linux" {
        return Err("platform must be windows or linux".to_owned());
    }
    let format = manifest["format"].as_str().unwrap_or_default();
    if format != "onnx" && format != "gguf" {
        return Err("format must be onnx or gguf".to_owned());
    }
    for field in ["sha256", "dataset_hash"] {
        let value = manifest[field].as_str().unwrap_or_default();
        if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("{field} must be a 64-char sha256 hex digest"));
        }
    }
    if let Some(metrics) = manifest.get("metrics") {
        let Some(metrics) = metrics.as_object() else {
            return Err("metrics must be an object".to_owned());
        };
        if metrics.values().any(|value| value.as_f64().is_none()) {
            return Err("metrics values must be numbers".to_owned());
        }
    }
    if let Some(limits) = manifest.get("limits") {
        if !limits.is_object() {
            return Err("limits must be an object".to_owned());
        }
    }
    match manifest.get("signature").and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err("signature must be a non-empty string".to_owned()),
    }
}

pub fn load_public_key(hex_key: &str) -> Result<VerifyingKey, String> {
    let bytes = decode_hex(hex_key).ok_or_else(|| "public key is not hex".to_owned())?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_owned())?;
    VerifyingKey::from_bytes(&array).map_err(|error| error.to_string())
}

pub fn private_key_from_hex(hex_key: &str) -> Result<SigningKey, String> {
    let bytes = decode_hex(hex_key).ok_or_else(|| "private key is not hex".to_owned())?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Ed25519 private key must be 32 bytes".to_owned())?;
    Ok(SigningKey::from_bytes(&array))
}

/// Dev-only keypair generation; production keys live in HSM/CI.
pub fn generate_dev_keypair() -> (String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let private_hex = hex_encode(&signing_key.to_bytes());
    let public_hex = hex_encode(&signing_key.verifying_key().to_bytes());
    (private_hex, public_hex)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}
