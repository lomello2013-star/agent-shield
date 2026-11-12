use std::path::{Path, PathBuf};

use aidf_core::response::{
    Action, CanaryStore, ConfirmationGate, ProcessController, QuarantineStore, ResponseExecutor,
};
use uuid::Uuid;

const KEY: &[u8; 32] = b"kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";

fn temp_root(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join(format!("aidf-response-{}-{name}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn write_file(root: &Path, name: &str, data: &[u8]) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, data).unwrap();
    path
}

#[test]
fn quarantine_roundtrip_restores_identical_bytes() {
    let root = temp_root("roundtrip");
    let original = write_file(&root, "malware.bin", b"MZpayload");
    let mut store = QuarantineStore::new(root.join("q"), KEY).unwrap();
    let entry = store.put(original.to_str().unwrap(), "test").unwrap();
    assert!(!original.exists());
    assert_eq!(entry.sha256.len(), 64);
    assert!(!store.list().is_empty());
    assert!(store.verify(&entry.quarantine_id));
    let dest = store.restore(&entry.quarantine_id, None).unwrap();
    assert_eq!(std::fs::read(dest).unwrap(), b"MZpayload");
    assert!(store.list().is_empty());
}

#[test]
fn quarantine_manifest_survives_restart() {
    let root = temp_root("restart");
    let file = write_file(&root, "a.txt", b"hello");
    let mut store = QuarantineStore::new(root.join("q"), KEY).unwrap();
    let entry = store.put(file.to_str().unwrap(), "").unwrap();
    let reopened = QuarantineStore::new(root.join("q"), KEY).unwrap();
    assert_eq!(reopened.list().len(), 1);
    assert_eq!(reopened.list()[0].quarantine_id, entry.quarantine_id);
    assert!(reopened.verify(&entry.quarantine_id));
}

#[test]
fn restore_refuses_to_overwrite() {
    let root = temp_root("overwrite");
    let file = write_file(&root, "a.txt", b"data");
    let mut store = QuarantineStore::new(root.join("q"), KEY).unwrap();
    let entry = store.put(file.to_str().unwrap(), "").unwrap();
    write_file(&root, "a.txt", b"new");
    assert!(store.restore(&entry.quarantine_id, None).is_err());
}

#[test]
fn tampered_blob_fails_authentication() {
    let root = temp_root("tamper");
    let file = write_file(&root, "a.txt", b"data");
    let mut store = QuarantineStore::new(root.join("q"), KEY).unwrap();
    let entry = store.put(file.to_str().unwrap(), "").unwrap();
    let blob_path = root.join("q").join(format!("{}.qtn", entry.quarantine_id));
    let mut blob = std::fs::read(&blob_path).unwrap();
    if let Some(last) = blob.last_mut() {
        *last ^= 0xFF;
    }
    std::fs::write(&blob_path, blob).unwrap();
    assert!(!store.verify(&entry.quarantine_id));
    assert!(store.restore(&entry.quarantine_id, None).is_err());
}

#[test]
fn missing_file_and_bad_key_rejected() {
    let root = temp_root("badkey");
    let mut store = QuarantineStore::new(root.join("q"), KEY).unwrap();
    assert!(store
        .put(root.join("nope.bin").to_str().unwrap(), "")
        .is_err());
    assert!(QuarantineStore::new(root.join("q2"), b"short").is_err());
}

#[test]
fn canary_detects_delete_and_modify() {
    let root = temp_root("canary");
    let mut store = CanaryStore::new(root.join("canary"));
    let files = store.create(3);
    assert_eq!(files.len(), 3);
    assert!(store.check().is_empty());
    std::fs::remove_file(&files[0]).unwrap();
    std::fs::write(&files[1], b"tampered").unwrap();
    let broken = store.check();
    assert!(broken.contains(&files[0]));
    assert!(broken.contains(&files[1]));
}

#[test]
fn process_controller_rejects_unknown_pid() {
    assert!(ProcessController::new().suspend(999_999_999).is_err());
}

struct Always;
impl ConfirmationGate for Always {
    fn executable(&self, _confirmation_id: &Uuid) -> bool {
        true
    }
}

struct Never;
impl ConfirmationGate for Never {
    fn executable(&self, _confirmation_id: &Uuid) -> bool {
        false
    }
}

#[test]
fn executor_notify_executes() {
    let executor = ResponseExecutor::new(Always);
    let result = executor.execute(&Action::new("notify", "x", true, false, None, "test"));
    assert_eq!(result.status, "executed");
}

#[test]
fn executor_refuses_without_confirmation() {
    let executor = ResponseExecutor::new(Always);
    let result = executor.execute(&Action::new("suspend", "1234", true, true, None, "test"));
    assert_eq!(result.status, "refused");
    assert_eq!(result.error, "confirmation_required");
}

#[test]
fn executor_refuses_unapproved_confirmation() {
    let executor = ResponseExecutor::new(Never);
    let result = executor.execute(&Action::new(
        "suspend",
        "1234",
        true,
        true,
        Some(Uuid::new_v4()),
        "test",
    ));
    assert_eq!(result.status, "refused");
    assert_eq!(result.error, "confirmation_not_approved");
}

#[test]
fn executor_refuses_terminate_and_network_actions() {
    let executor = ResponseExecutor::new(Always);
    let terminate = executor.execute(&Action::new(
        "terminate",
        "1234",
        false,
        false,
        None,
        "test",
    ));
    assert_eq!(terminate.status, "refused");
    let network = executor.execute(&Action::new(
        "block_network",
        "10.0.0.1:445",
        true,
        false,
        None,
        "test",
    ));
    assert_eq!(network.status, "failed");
    assert!(network.error.contains("not supported"));
}

#[test]
fn executor_quarantines_with_approved_confirmation() {
    let root = temp_root("executor");
    let file = write_file(&root, "bad.bin", b"evil");
    let store = QuarantineStore::new(root.join("q"), KEY).unwrap();
    let executor = ResponseExecutor::new(Always).with_quarantine(store);
    let result = executor.execute(&Action::new(
        "quarantine",
        file.to_str().unwrap(),
        true,
        true,
        Some(Uuid::new_v4()),
        "test",
    ));
    assert_eq!(result.status, "executed");
    assert!(!file.exists());
    let reopened = QuarantineStore::new(root.join("q"), KEY).unwrap();
    assert_eq!(reopened.list().len(), 1);
}
