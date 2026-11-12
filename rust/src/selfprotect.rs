//! User-mode self-protection — Rust port of `core/selfprotect.py`.
//!
//! Append-only hash-chained audit log with a signed checkpoint (anchor), a sealed
//! integrity manifest, and a startup self-test. Kernel mechanisms (PPL/ELAM/
//! fs-verity/IMA) remain out of scope.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};

use crate::sha256::sha256_hex;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    pub ok: bool,
    pub records: i64,
    pub broken_at: Option<i64>,
    pub reason: String,
}

impl VerifyResult {
    fn ok(records: i64) -> Self {
        Self {
            ok: true,
            records,
            broken_at: None,
            reason: String::new(),
        }
    }

    fn broken(records: i64, broken_at: Option<i64>, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            records,
            broken_at,
            reason: reason.into(),
        }
    }
}

type NowFn = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

fn canonical(payload: &Value) -> Vec<u8> {
    // serde_json's Map is ordered; canonicalise explicitly with a BTreeMap to
    // match Python `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let sorted: BTreeMap<String, Value> = map
                    .iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect();
                Value::Object(sorted.into_iter().collect())
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sort(payload)).unwrap_or_default()
}

pub struct HashChainLog {
    pub path: PathBuf,
    pub anchor_path: Option<PathBuf>,
    pub fsync_every: usize,
    now_fn: NowFn,
    last_seq: i64,
    last_hash: String,
    buffer: Vec<String>,
    verified_seq: i64,
    verified_hash: String,
    offset: u64,
}

impl HashChainLog {
    pub fn new(path: impl AsRef<Path>, anchor_path: Option<PathBuf>, fsync_every: usize) -> Self {
        Self::with_clock(path, anchor_path, fsync_every, Arc::new(Utc::now))
    }

    pub fn with_clock(
        path: impl AsRef<Path>,
        anchor_path: Option<PathBuf>,
        fsync_every: usize,
        now_fn: NowFn,
    ) -> Self {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut log = Self {
            path,
            anchor_path,
            fsync_every: fsync_every.max(1),
            now_fn,
            last_seq: 0,
            last_hash: GENESIS.to_owned(),
            buffer: Vec::new(),
            verified_seq: 0,
            verified_hash: GENESIS.to_owned(),
            offset: 0,
        };
        log.recover();
        log
    }

    fn recover(&mut self) {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(object) = record.as_object() else {
                continue;
            };
            if let (Some(seq), Some(hash)) = (
                object.get("seq").and_then(Value::as_i64),
                object.get("hash").and_then(Value::as_str),
            ) {
                self.last_seq = seq;
                self.last_hash = hash.to_owned();
            }
        }
    }

    fn anchor(&self) -> Option<Value> {
        let path = self.anchor_path.as_ref()?;
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn append(&mut self, kind: &str, payload: Value) -> Value {
        let seq = self.last_seq + 1;
        let body = json!({
            "seq": seq,
            "ts": (self.now_fn)().to_rfc3339_opts(SecondsFormat::Micros, false),
            "type": kind,
            "payload": payload,
            "prev": self.last_hash,
        });
        let digest = sha256_hex(&canonical(&body));
        let record = json!({
            "seq": body["seq"],
            "ts": body["ts"],
            "type": body["type"],
            "payload": body["payload"],
            "prev": body["prev"],
            "hash": digest,
        });
        let line = format!("{}\n", serde_json::to_string(&record).unwrap_or_default());
        self.last_seq = seq;
        self.last_hash = digest;
        if self.fsync_every == 1 {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = file.write_all(line.as_bytes());
                let _ = file.flush();
                let _ = file.sync_data();
            }
        } else {
            self.buffer.push(line);
            if self.buffer.len() >= self.fsync_every {
                self.flush();
            }
        }
        record
    }

    pub fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = file.write_all(self.buffer.concat().as_bytes());
            let _ = file.flush();
            let _ = file.sync_data();
        }
        self.buffer.clear();
    }

    pub fn close(&mut self) {
        self.flush();
    }

    pub fn seal(&mut self) -> Result<Value, String> {
        let anchor_path = self
            .anchor_path
            .clone()
            .ok_or_else(|| "no anchor_path configured".to_owned())?;
        self.flush();
        let full = self.verify(false);
        if !full.ok {
            return Err(format!(
                "refusing to seal an invalid chain: {}",
                full.reason
            ));
        }
        let anchor = json!({
            "seq": self.last_seq,
            "hash": self.last_hash,
            "sealed_at": (self.now_fn)().to_rfc3339_opts(SecondsFormat::Micros, false),
        });
        let tmp = PathBuf::from(format!("{}.tmp", anchor_path.display()));
        std::fs::write(&tmp, serde_json::to_vec(&anchor).unwrap_or_default())
            .map_err(|error| error.to_string())?;
        std::fs::rename(&tmp, &anchor_path).map_err(|error| error.to_string())?;
        Ok(anchor)
    }

    pub fn verify(&mut self, incremental: bool) -> VerifyResult {
        if !self.path.exists() {
            return VerifyResult::ok(0);
        }
        let mut text = String::new();
        let start_offset = self.offset;
        let mut offset = start_offset;
        if incremental {
            if let Ok(mut file) = File::open(&self.path) {
                if file.seek(SeekFrom::Start(offset)).is_ok() {
                    let _ = file.read_to_string(&mut text);
                    offset = start_offset + text.len() as u64;
                } else {
                    text.clear();
                }
            }
        } else {
            text = std::fs::read_to_string(&self.path).unwrap_or_default();
            offset = text.len() as u64;
        }

        let mut prev = if incremental {
            self.verified_hash.clone()
        } else {
            GENESIS.to_owned()
        };
        let mut seq_expected = if incremental {
            self.verified_seq + 1
        } else {
            1
        };
        let mut count = if incremental { self.verified_seq } else { 0 };

        for raw in text.lines() {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let record: Value = match serde_json::from_str(raw) {
                Ok(record) => record,
                Err(_) => return VerifyResult::broken(count, Some(count + 1), "unparsable record"),
            };
            let Some(object) = record.as_object() else {
                return VerifyResult::broken(count, Some(count + 1), "record must be an object");
            };
            let required = ["seq", "ts", "type", "payload", "prev", "hash"];
            let missing: Vec<&str> = required
                .iter()
                .filter(|field| !object.contains_key(**field))
                .copied()
                .collect();
            if !missing.is_empty() {
                return VerifyResult::broken(
                    count,
                    object.get("seq").and_then(Value::as_i64),
                    format!("malformed record: missing {missing:?}"),
                );
            }
            if object.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
                return VerifyResult::broken(
                    count,
                    object.get("seq").and_then(Value::as_i64),
                    "prev hash mismatch",
                );
            }
            let body = json!({
                "seq": object["seq"],
                "ts": object["ts"],
                "type": object["type"],
                "payload": object["payload"],
                "prev": object["prev"],
            });
            if sha256_hex(&canonical(&body)) != object["hash"].as_str().unwrap_or_default() {
                return VerifyResult::broken(
                    count,
                    object.get("seq").and_then(Value::as_i64),
                    "record hash mismatch",
                );
            }
            if object["seq"].as_i64() != Some(seq_expected) {
                return VerifyResult::broken(
                    count,
                    object.get("seq").and_then(Value::as_i64),
                    "sequence gap",
                );
            }
            prev = object["hash"].as_str().unwrap_or_default().to_owned();
            seq_expected += 1;
            count += 1;
        }

        self.verified_seq = count;
        self.verified_hash = prev.clone();
        self.offset = offset;

        if let Some(anchor) = self.anchor() {
            let anchor_seq = anchor.get("seq").and_then(Value::as_i64).unwrap_or(0);
            let anchor_hash = anchor
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if anchor_seq > count {
                return VerifyResult::broken(
                    count,
                    None,
                    format!("truncation: anchor seq {anchor_seq} > chain {count}"),
                );
            }
            if anchor_seq == count && anchor_hash != prev {
                return VerifyResult::broken(count, None, "anchor hash mismatch");
            }
        }
        VerifyResult::ok(count)
    }

    pub fn verified_records(&self) -> i64 {
        self.verified_seq
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityResult {
    pub ok: bool,
    pub modified: Vec<String>,
    pub missing: Vec<String>,
    pub added: Vec<String>,
    pub checked: usize,
}

pub struct IntegrityManifest {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub files: BTreeMap<String, String>,
}

impl IntegrityManifest {
    pub fn new(root: impl AsRef<Path>, manifest_path: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            manifest_path: manifest_path.as_ref().to_path_buf(),
            files: BTreeMap::new(),
        }
    }

    fn rel(&self, path: &Path) -> String {
        let absolute = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let root = std::fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone());
        absolute
            .strip_prefix(root)
            .unwrap_or(&absolute)
            .to_string_lossy()
            .replace('\\', "/")
    }

    fn sha256(path: &Path) -> String {
        std::fs::read(path)
            .map(|bytes| sha256_hex(&bytes))
            .unwrap_or_default()
    }

    pub fn seal(&mut self, paths: &[PathBuf]) -> BTreeMap<String, String> {
        let mut sorted = paths.to_vec();
        sorted.sort();
        self.files = sorted
            .into_iter()
            .filter(|path| path.exists())
            .map(|path| (self.rel(&path), Self::sha256(&path)))
            .collect();
        let payload = json!({"files": self.files});
        let tmp = self.manifest_path.with_extension("tmp");
        let _ = std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&payload).unwrap_or_default(),
        );
        let _ = std::fs::rename(tmp, &self.manifest_path);
        self.files.clone()
    }

    pub fn load(&mut self) -> Result<BTreeMap<String, String>, String> {
        let text = std::fs::read_to_string(&self.manifest_path).map_err(|e| e.to_string())?;
        let payload: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let files = payload
            .get("files")
            .and_then(Value::as_object)
            .ok_or_else(|| "manifest has no files".to_owned())?;
        self.files = files
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
            .collect();
        Ok(self.files.clone())
    }

    pub fn verify(&self) -> IntegrityResult {
        let mut current = BTreeMap::new();
        for rel in self.files.keys() {
            let path = self.root.join(rel);
            if path.exists() {
                current.insert(rel.clone(), Self::sha256(&path));
            }
        }
        let modified: Vec<String> = self
            .files
            .iter()
            .filter(|(rel, digest)| current.get(*rel).is_some_and(|actual| actual != *digest))
            .map(|(rel, _)| rel.clone())
            .collect();
        let missing: Vec<String> = self
            .files
            .keys()
            .filter(|rel| !current.contains_key(*rel))
            .cloned()
            .collect();
        let mut added = Vec::new();
        let manifest_rel = self.rel(&self.manifest_path);
        self.walk(&self.root, &mut |path| {
            let rel = self.rel(path);
            if rel != manifest_rel && !self.files.contains_key(&rel) {
                added.push(rel);
            }
        });
        added.sort();
        IntegrityResult {
            ok: modified.is_empty() && missing.is_empty(),
            modified,
            missing,
            added,
            checked: self.files.len(),
        }
    }

    fn walk(&self, root: &Path, visit: &mut impl FnMut(&Path)) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.walk(&path, visit);
            } else {
                visit(&path);
            }
        }
    }
}

type CheckFn = Arc<dyn Fn() -> (bool, String) + Send + Sync>;

#[derive(Default)]
pub struct SelfTest {
    checks: BTreeMap<String, CheckFn>,
}

impl SelfTest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<F>(&mut self, name: &str, check: F)
    where
        F: Fn() -> (bool, String) + Send + Sync + 'static,
    {
        self.checks.insert(name.to_owned(), Arc::new(check));
    }

    pub fn run(&self) -> Value {
        let started = Instant::now();
        let mut results = Vec::new();
        for (name, check) in &self.checks {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check()));
            let (ok, detail) = match outcome {
                Ok(value) => value,
                Err(_) => (false, "check panicked".to_owned()),
            };
            results.push(json!({"check": name, "ok": ok, "detail": detail}));
        }
        let failed: Vec<&str> = results
            .iter()
            .filter(|result| result["ok"] == Value::Bool(false))
            .filter_map(|result| result["check"].as_str())
            .collect();
        json!({
            "ok": failed.is_empty(),
            "checks": results,
            "failed": failed,
            "duration_ms": round3(started.elapsed().as_secs_f64() * 1000.0),
        })
    }
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}
