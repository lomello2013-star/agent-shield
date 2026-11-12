use std::path::{Path, PathBuf};

use aidf_core::selfprotect::{HashChainLog, IntegrityManifest, SelfTest};
use chrono::{DateTime, Utc};
use serde_json::Value;

fn temp_root(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp")
        .join(format!("aidf-self-{}-{name}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn fixed_time() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-12T12:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc)
}

fn make_log(root: &Path) -> HashChainLog {
    let now = fixed_time();
    HashChainLog::with_clock(
        root.join("audit").join("chain.jsonl"),
        Some(root.join("audit").join("anchor.json")),
        1,
        std::sync::Arc::new(move || now),
    )
}

#[test]
fn append_and_verify() {
    let root = temp_root("append");
    let mut log = make_log(&root);
    for i in 0..5 {
        log.append("test", serde_json::json!({"i": i}));
    }
    let result = log.verify(false);
    assert!(result.ok);
    assert_eq!(result.records, 5);
}

#[test]
fn record_links_to_previous_hash() {
    let root = temp_root("links");
    let mut log = make_log(&root);
    let first = log.append("a", serde_json::json!({"x": 1}));
    let second = log.append("b", serde_json::json!({"x": 2}));
    assert_eq!(first["prev"], "0".repeat(64));
    assert_eq!(second["prev"], first["hash"]);
}

#[test]
fn modified_payload_detected() {
    let root = temp_root("modified");
    let mut log = make_log(&root);
    log.append("a", serde_json::json!({"x": 1}));
    log.append("b", serde_json::json!({"x": 2}));
    let text = std::fs::read_to_string(&log.path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut record: Value = serde_json::from_str(&lines[0]).unwrap();
    record["payload"]["x"] = serde_json::json!(999);
    lines[0] = serde_json::to_string(&record).unwrap();
    std::fs::write(&log.path, format!("{}\n", lines.join("\n"))).unwrap();
    let mut reopened = HashChainLog::new(&log.path, None, 1);
    let result = reopened.verify(false);
    assert!(!result.ok);
    assert!(result.reason.contains("hash mismatch"));
}

#[test]
fn deleted_middle_record_detected() {
    let root = temp_root("deleted");
    let mut log = make_log(&root);
    for i in 0..4 {
        log.append("a", serde_json::json!({"i": i}));
    }
    let text = std::fs::read_to_string(&log.path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(
        &log.path,
        format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]),
    )
    .unwrap();
    let mut reopened = HashChainLog::new(&log.path, None, 1);
    assert!(!reopened.verify(false).ok);
}

#[test]
fn reordered_records_detected() {
    let root = temp_root("reordered");
    let mut log = make_log(&root);
    for i in 0..3 {
        log.append("a", serde_json::json!({"i": i}));
    }
    let text = std::fs::read_to_string(&log.path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(
        &log.path,
        format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]),
    )
    .unwrap();
    let mut reopened = HashChainLog::new(&log.path, None, 1);
    assert!(!reopened.verify(false).ok);
}

#[test]
fn truncation_detected_with_anchor() {
    let root = temp_root("truncation");
    let mut log = make_log(&root);
    for i in 0..5 {
        log.append("a", serde_json::json!({"i": i}));
    }
    log.seal().unwrap();
    let text = std::fs::read_to_string(&log.path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    std::fs::write(&log.path, format!("{}\n", lines[..3].join("\n"))).unwrap();
    let mut reopened = HashChainLog::new(&log.path, log.anchor_path.clone(), 1);
    let result = reopened.verify(false);
    assert!(!result.ok);
    assert!(result.reason.contains("truncation"));
}

#[test]
fn append_after_reopen_continues_chain() {
    let root = temp_root("reopen");
    let mut log = make_log(&root);
    log.append("a", serde_json::json!({"i": 1}));
    let mut reopened = HashChainLog::with_clock(
        &log.path,
        log.anchor_path.clone(),
        1,
        std::sync::Arc::new(fixed_time),
    );
    reopened.append("b", serde_json::json!({"i": 2}));
    assert_eq!(reopened.verify(false).records, 2);
}

#[test]
fn unparsable_line_detected() {
    let root = temp_root("unparsable");
    let mut log = make_log(&root);
    log.append("a", serde_json::json!({}));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log.path)
        .unwrap();
    use std::io::Write;
    file.write_all(b"{not json}\n").unwrap();
    let mut reopened = HashChainLog::new(&log.path, None, 1);
    assert!(!reopened.verify(false).ok);
}

#[test]
fn forged_record_without_required_keys_is_tamper_not_crash() {
    let root = temp_root("forged");
    let mut log = make_log(&root);
    log.append("a", serde_json::json!({}));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log.path)
        .unwrap();
    use std::io::Write;
    file.write_all(b"{\"forged\": true}\n").unwrap();
    let mut reopened = HashChainLog::new(&log.path, None, 1);
    let result = reopened.verify(false);
    assert!(!result.ok);
    assert!(result.reason.contains("malformed record"));
}

#[test]
fn seal_requires_anchor() {
    let root = temp_root("seal");
    let mut log = HashChainLog::new(root.join("x.jsonl"), None, 1);
    assert!(log.seal().is_err());
}

#[test]
fn batched_append_flushes_on_threshold() {
    let root = temp_root("batch");
    let mut log = HashChainLog::new(root.join("log.jsonl"), None, 4);
    for i in 0..3 {
        log.append("a", serde_json::json!({"i": i}));
    }
    assert!(!log.path.exists() || std::fs::metadata(&log.path).unwrap().len() == 0);
    log.flush();
    assert_eq!(log.verify(false).records, 3);
}

#[test]
fn incremental_verify_reads_tail() {
    let root = temp_root("incremental");
    let mut log = make_log(&root);
    log.append("a", serde_json::json!({"i": 1}));
    log.append("b", serde_json::json!({"i": 2}));
    assert_eq!(log.verify(false).records, 2);
    log.append("c", serde_json::json!({"i": 3}));
    log.append("d", serde_json::json!({"i": 4}));
    let result = log.verify(true);
    assert!(result.ok);
    assert_eq!(result.records, 4);
}

#[test]
fn integrity_manifest_detects_modification_and_addition() {
    let root = temp_root("integrity");
    let file_a = root.join("a.txt");
    let file_b = root.join("b.txt");
    std::fs::write(&file_a, b"alpha").unwrap();
    std::fs::write(&file_b, b"beta").unwrap();
    let mut manifest = IntegrityManifest::new(&root, root.join("manifest.json"));
    let sealed = manifest.seal(&[file_a.clone(), file_b.clone()]);
    assert_eq!(sealed.len(), 2);
    assert!(manifest.verify().ok);

    std::fs::write(&file_a, b"changed").unwrap();
    let result = manifest.verify();
    assert!(!result.ok);
    assert_eq!(result.modified, vec!["a.txt".to_owned()]);

    std::fs::write(root.join("added.txt"), b"new").unwrap();
    let result = manifest.verify();
    assert!(result.added.contains(&"added.txt".to_owned()));
}

#[test]
fn self_test_reports_pass_and_failure_and_panic() {
    let mut suite = SelfTest::new();
    suite.register("ok", || (true, "fine".to_owned()));
    suite.register("bad", || (false, "broken".to_owned()));
    suite.register("panic", || panic!("boom"));
    let report = suite.run();
    assert_eq!(report["ok"], Value::Bool(false));
    assert_eq!(report["failed"].as_array().unwrap().len(), 2);
}
