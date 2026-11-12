//! Response actions — Rust port of `core/response.py`.
//!
//! Reversible actions only: suspend/resume, encrypted quarantine/restore, canary
//! checks and notify. Irreversible `terminate` is refused; network blocking is
//! explicitly unsupported in user-mode.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::sha256::sha256_hex;

pub const QUARANTINE_MAGIC: &[u8; 6] = b"AIDFQ1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionError(pub String);

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ActionError {}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct QuarantineEntry {
    pub quarantine_id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub created_at: f64,
    pub reason: String,
}

pub struct QuarantineStore {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    cipher: Aes256Gcm,
    entries: std::collections::HashMap<String, QuarantineEntry>,
}

impl QuarantineStore {
    pub fn new(root: impl AsRef<Path>, key: &[u8]) -> Result<Self, ActionError> {
        if key.len() != 32 {
            return Err(ActionError("AES-256-GCM key must be 32 bytes".to_owned()));
        }
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|error| ActionError(error.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| ActionError("invalid AES-256-GCM key".to_owned()))?;
        let mut store = Self {
            manifest_path: root.join("manifest.json"),
            root,
            cipher,
            entries: std::collections::HashMap::new(),
        };
        store.load();
        Ok(store)
    }

    fn load(&mut self) {
        let Ok(text) = std::fs::read_to_string(&self.manifest_path) else {
            return;
        };
        let Ok(payload) = serde_json::from_str::<Value>(&text) else {
            return;
        };
        let Some(items) = payload.get("entries").and_then(Value::as_array) else {
            return;
        };
        for item in items {
            if let Ok(entry) = serde_json::from_value::<QuarantineEntry>(item.clone()) {
                self.entries.insert(entry.quarantine_id.clone(), entry);
            }
        }
    }

    fn save(&self) -> Result<(), ActionError> {
        let entries: Vec<&QuarantineEntry> = self.entries.values().collect();
        let payload = json!({"entries": entries});
        let tmp = PathBuf::from(format!("{}.tmp", self.manifest_path.display()));
        let bytes = serde_json::to_vec_pretty(&payload).map_err(|e| ActionError(e.to_string()))?;
        std::fs::write(&tmp, bytes).map_err(|e| ActionError(e.to_string()))?;
        std::fs::rename(&tmp, &self.manifest_path).map_err(|e| ActionError(e.to_string()))
    }

    fn blob_path(&self, quarantine_id: &str) -> PathBuf {
        self.root.join(format!("{quarantine_id}.qtn"))
    }

    pub fn put(&mut self, path: &str, reason: &str) -> Result<QuarantineEntry, ActionError> {
        let src = absolute(path);
        if !src.exists() {
            return Err(ActionError(format!("file not found: {path}")));
        }
        let metadata =
            std::fs::symlink_metadata(&src).map_err(|error| ActionError(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(ActionError("refusing to quarantine a symlink".to_owned()));
        }
        let data = std::fs::read(&src).map_err(|error| ActionError(error.to_string()))?;
        let digest = sha256_hex(&data);
        let qid = Uuid::new_v4().simple().to_string();
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &data,
                    aad: qid.as_bytes(),
                },
            )
            .map_err(|_| ActionError("quarantine encryption failed".to_owned()))?;
        let mut blob = Vec::with_capacity(QUARANTINE_MAGIC.len() + 12 + ciphertext.len());
        blob.extend_from_slice(QUARANTINE_MAGIC);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        let blob_path = self.blob_path(&qid);
        let mut file = File::create(&blob_path).map_err(|e| ActionError(e.to_string()))?;
        file.write_all(&blob)
            .map_err(|e| ActionError(e.to_string()))?;
        file.flush().map_err(|e| ActionError(e.to_string()))?;
        file.sync_data().map_err(|e| ActionError(e.to_string()))?;

        let entry = QuarantineEntry {
            quarantine_id: qid.clone(),
            original_path: src.to_string_lossy().to_string(),
            sha256: digest,
            size: data.len() as u64,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs_f64())
                .unwrap_or(0.0),
            reason: reason.to_owned(),
        };
        self.entries.insert(qid, entry.clone());
        self.save()?;
        std::fs::remove_file(&src).map_err(|e| ActionError(e.to_string()))?;
        Ok(entry)
    }

    pub fn restore(
        &mut self,
        quarantine_id: &str,
        target: Option<&str>,
    ) -> Result<String, ActionError> {
        let entry = self
            .entries
            .get(quarantine_id)
            .cloned()
            .ok_or_else(|| ActionError(format!("unknown quarantine id: {quarantine_id}")))?;
        let dest = absolute(target.unwrap_or(&entry.original_path));
        if dest.exists() {
            return Err(ActionError(format!(
                "refusing to overwrite existing file: {}",
                dest.display()
            )));
        }
        let blob_path = self.blob_path(quarantine_id);
        let blob = std::fs::read(&blob_path).map_err(|e| ActionError(e.to_string()))?;
        if !blob.starts_with(QUARANTINE_MAGIC) || blob.len() < QUARANTINE_MAGIC.len() + 12 {
            return Err(ActionError("quarantine blob has bad magic".to_owned()));
        }
        let nonce = Nonce::from_slice(&blob[QUARANTINE_MAGIC.len()..QUARANTINE_MAGIC.len() + 12]);
        let ciphertext = &blob[QUARANTINE_MAGIC.len() + 12..];
        let data = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: quarantine_id.as_bytes(),
                },
            )
            .map_err(|_| ActionError("quarantine blob failed authentication".to_owned()))?;
        if sha256_hex(&data) != entry.sha256 {
            return Err(ActionError("restored content hash mismatch".to_owned()));
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ActionError(e.to_string()))?;
        }
        let mut file = File::create(&dest).map_err(|e| ActionError(e.to_string()))?;
        file.write_all(&data)
            .map_err(|e| ActionError(e.to_string()))?;
        file.flush().map_err(|e| ActionError(e.to_string()))?;
        file.sync_data().map_err(|e| ActionError(e.to_string()))?;
        let _ = std::fs::remove_file(&blob_path);
        self.entries.remove(quarantine_id);
        self.save()?;
        Ok(dest.to_string_lossy().to_string())
    }

    pub fn list(&self) -> Vec<QuarantineEntry> {
        self.entries.values().cloned().collect()
    }

    pub fn verify(&self, quarantine_id: &str) -> bool {
        let Some(entry) = self.entries.get(quarantine_id) else {
            return false;
        };
        let Ok(blob) = std::fs::read(self.blob_path(quarantine_id)) else {
            return false;
        };
        if !blob.starts_with(QUARANTINE_MAGIC) || blob.len() < QUARANTINE_MAGIC.len() + 12 {
            return false;
        }
        let nonce = Nonce::from_slice(&blob[QUARANTINE_MAGIC.len()..QUARANTINE_MAGIC.len() + 12]);
        let ciphertext = &blob[QUARANTINE_MAGIC.len() + 12..];
        let Ok(data) = self.cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: quarantine_id.as_bytes(),
            },
        ) else {
            return false;
        };
        sha256_hex(&data) == entry.sha256
    }
}

fn absolute(path: &str) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path))
}

pub struct CanaryStore {
    pub root: PathBuf,
    pub files: Vec<PathBuf>,
}

impl CanaryStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            files: Vec::new(),
        }
    }

    pub fn create(&mut self, count: usize) -> Vec<PathBuf> {
        let _ = std::fs::create_dir_all(&self.root);
        let mut out = Vec::new();
        for index in 0..count {
            let path = self.root.join(format!("canary_{index}.txt"));
            let _ = std::fs::write(&path, format!("aidf-canary-{index}-{}\n", Uuid::new_v4()));
            out.push(path);
        }
        self.files = out.clone();
        out
    }

    pub fn check(&self) -> Vec<PathBuf> {
        let mut broken = Vec::new();
        for path in &self.files {
            if !path.exists() {
                broken.push(path.clone());
                continue;
            }
            match std::fs::read_to_string(path) {
                Ok(text) if text.starts_with("aidf-canary-") => {}
                _ => broken.push(path.clone()),
            }
        }
        broken
    }
}

pub struct ProcessController;

impl ProcessController {
    pub fn new() -> Self {
        Self
    }

    pub fn supported(&self) -> bool {
        cfg!(any(windows, target_os = "linux"))
    }

    pub fn suspend(&self, pid: u32) -> Result<(), ActionError> {
        platform::suspend(pid)
    }

    pub fn resume(&self, pid: u32) -> Result<(), ActionError> {
        platform::resume(pid)
    }
}

impl Default for ProcessController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
mod platform {
    use super::ActionError;
    use libloading::Library;
    use std::ffi::c_void;

    type Handle = *mut c_void;

    fn open_process(pid: u32) -> Result<(Handle, Library), ActionError> {
        unsafe {
            let kernel32 =
                Library::new("kernel32.dll").map_err(|error| ActionError(error.to_string()))?;
            let open: libloading::Symbol<unsafe extern "system" fn(u32, i32, u32) -> Handle> =
                kernel32
                    .get(b"OpenProcess")
                    .map_err(|error| ActionError(error.to_string()))?;
            let handle = open(0x0800, 0, pid);
            if handle.is_null() {
                return Err(ActionError(format!("OpenProcess failed for pid {pid}")));
            }
            Ok((handle, kernel32))
        }
    }

    fn close_process(handle: Handle, kernel32: &Library) {
        unsafe {
            if let Ok(close) =
                kernel32.get::<unsafe extern "system" fn(Handle) -> i32>(b"CloseHandle")
            {
                close(handle);
            }
        }
    }

    fn call(pid: u32, symbol: &[u8]) -> Result<(), ActionError> {
        unsafe {
            let (handle, kernel32) = open_process(pid)?;
            let ntdll =
                Library::new("ntdll.dll").map_err(|error| ActionError(error.to_string()))?;
            let function: libloading::Symbol<unsafe extern "system" fn(Handle) -> i32> = ntdll
                .get(symbol)
                .map_err(|error| ActionError(error.to_string()))?;
            let status = function(handle);
            close_process(handle, &kernel32);
            if status != 0 {
                return Err(ActionError(format!(
                    "{} failed: 0x{:08X}",
                    String::from_utf8_lossy(symbol),
                    status as u32
                )));
            }
            Ok(())
        }
    }

    pub(super) fn suspend(pid: u32) -> Result<(), ActionError> {
        call(pid, b"NtSuspendProcess")
    }

    pub(super) fn resume(pid: u32) -> Result<(), ActionError> {
        call(pid, b"NtResumeProcess")
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::ActionError;

    pub(super) fn suspend(pid: u32) -> Result<(), ActionError> {
        let status = unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
        if status == 0 {
            Ok(())
        } else {
            Err(ActionError(format!("kill(SIGSTOP) failed for pid {pid}")))
        }
    }

    pub(super) fn resume(pid: u32) -> Result<(), ActionError> {
        let status = unsafe { libc::kill(pid as i32, libc::SIGCONT) };
        if status == 0 {
            Ok(())
        } else {
            Err(ActionError(format!("kill(SIGCONT) failed for pid {pid}")))
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod platform {
    use super::ActionError;

    pub(super) fn suspend(_pid: u32) -> Result<(), ActionError> {
        Err(ActionError("process control unsupported".to_owned()))
    }

    pub(super) fn resume(_pid: u32) -> Result<(), ActionError> {
        Err(ActionError("process control unsupported".to_owned()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub type_: String,
    pub target: String,
    pub reversible: bool,
    pub requires_confirmation: bool,
    pub confirmation_id: Option<Uuid>,
    pub platform_effect: String,
    pub status: String,
}

impl Action {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        type_: &str,
        target: &str,
        reversible: bool,
        requires_confirmation: bool,
        confirmation_id: Option<Uuid>,
        platform_effect: &str,
    ) -> Self {
        Self {
            type_: type_.to_owned(),
            target: target.to_owned(),
            reversible,
            requires_confirmation,
            confirmation_id,
            platform_effect: platform_effect.to_owned(),
            status: "pending".to_owned(),
        }
    }
}

pub trait ConfirmationGate {
    fn executable(&self, confirmation_id: &Uuid) -> bool;
}

impl ConfirmationGate for crate::confirm::ConfirmationManager {
    fn executable(&self, confirmation_id: &Uuid) -> bool {
        self.executable_uuid(confirmation_id)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionResult {
    pub action: Action,
    pub status: String,
    pub error: String,
    pub duration_ms: f64,
}

pub struct ResponseExecutor<G: ConfirmationGate> {
    pub confirmations: G,
    pub processes: ProcessController,
    pub quarantine: Option<Mutex<QuarantineStore>>,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl<G: ConfirmationGate> ResponseExecutor<G> {
    pub fn new(confirmations: G) -> Self {
        let origin = Instant::now();
        Self {
            confirmations,
            processes: ProcessController::new(),
            quarantine: None,
            clock: Arc::new(move || origin.elapsed().as_secs_f64()),
        }
    }

    pub fn with_quarantine(mut self, quarantine: QuarantineStore) -> Self {
        self.quarantine = Some(Mutex::new(quarantine));
        self
    }

    pub fn execute(&self, action: &Action) -> ExecutionResult {
        let refused = |error: &str| ExecutionResult {
            action: action.clone(),
            status: "refused".to_owned(),
            error: error.to_owned(),
            duration_ms: 0.0,
        };
        if action.type_ == "terminate" {
            return refused("irreversible action requires human approval path");
        }
        if action.type_ == "block_network" || action.type_ == "unblock_network" {
            return ExecutionResult {
                action: action.clone(),
                status: "failed".to_owned(),
                error: format!("action not supported in user-mode: {}", action.type_),
                duration_ms: 0.0,
            };
        }
        if action.requires_confirmation {
            let Some(confirmation_id) = action.confirmation_id else {
                return refused("confirmation_required");
            };
            if !self.confirmations.executable(&confirmation_id) {
                return refused("confirmation_not_approved");
            }
        }
        let started = (self.clock)();
        let result = match action.type_.as_str() {
            "suspend" => action
                .target
                .parse::<u32>()
                .map_err(|_| ActionError("invalid pid".to_owned()))
                .and_then(|pid| self.processes.suspend(pid)),
            "resume" => action
                .target
                .parse::<u32>()
                .map_err(|_| ActionError("invalid pid".to_owned()))
                .and_then(|pid| self.processes.resume(pid)),
            "quarantine" => self
                .quarantine
                .as_ref()
                .ok_or_else(|| ActionError("quarantine store not configured".to_owned()))
                .and_then(|store| {
                    store
                        .lock()
                        .map_err(|_| ActionError("quarantine store lock poisoned".to_owned()))?
                        .put(&action.target, &action.platform_effect)
                        .map(|_| ())
                }),
            "restore" => self
                .quarantine
                .as_ref()
                .ok_or_else(|| ActionError("quarantine store not configured".to_owned()))
                .and_then(|store| {
                    store
                        .lock()
                        .map_err(|_| ActionError("quarantine store lock poisoned".to_owned()))?
                        .restore(&action.target, None)
                        .map(|_| ())
                }),
            "notify" => Ok(()),
            other => Err(ActionError(format!("unknown action type: {other}"))),
        };
        let duration_ms = ((self.clock)() - started) * 1000.0;
        match result {
            Ok(()) => ExecutionResult {
                action: action.clone(),
                status: "executed".to_owned(),
                error: String::new(),
                duration_ms: round3(duration_ms),
            },
            Err(error) => ExecutionResult {
                action: action.clone(),
                status: "failed".to_owned(),
                error: error.0,
                duration_ms: round3(duration_ms),
            },
        }
    }
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}
