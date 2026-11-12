//! Confirmation gate with fail-safe timeout — Rust port of `core/confirm.py`.
//!
//! Reversible actions may run on policy + confidence. Destructive actions require
//! an operator; without one they are queued, never executed. Timeouts always
//! resolve to `FAIL_SAFE_ON_TIMEOUT` ("reject").

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use uuid::Uuid;

use crate::policy::FAIL_SAFE_ON_TIMEOUT;

pub const DESTRUCTIVE_ACTIONS: [&str; 4] = ["terminate", "delete", "remove", "wipe"];

#[derive(Clone, Debug, PartialEq)]
pub struct Confirmation {
    pub action_id: String,
    pub level: String,
    pub timeout_s: f64,
    pub created_at: f64,
    pub destructive: bool,
    pub queued: bool,
    pub decision: String,
    pub decided_by: Option<String>,
    pub confirmation_id: String,
}

impl Confirmation {
    pub fn new(action_id: &str, level: &str, timeout_s: f64, created_at: f64) -> Self {
        Self {
            action_id: action_id.to_owned(),
            level: level.to_owned(),
            timeout_s,
            created_at,
            destructive: false,
            queued: false,
            decision: "pending".to_owned(),
            decided_by: None,
            confirmation_id: Uuid::new_v4().to_string(),
        }
    }
}

type NowFn = Arc<dyn Fn() -> f64 + Send + Sync>;

pub struct ConfirmationManager {
    pub default_timeout_s: f64,
    pub operator_present: bool,
    now_fn: NowFn,
    items: HashMap<String, Confirmation>,
}

impl ConfirmationManager {
    pub fn new(default_timeout_s: f64, operator_present: bool) -> Self {
        let origin = Instant::now();
        Self::with_clock(
            default_timeout_s,
            operator_present,
            Arc::new(move || origin.elapsed().as_secs_f64()),
        )
    }

    pub fn with_clock(default_timeout_s: f64, operator_present: bool, now_fn: NowFn) -> Self {
        Self {
            default_timeout_s,
            operator_present,
            now_fn,
            items: HashMap::new(),
        }
    }

    pub fn request(
        &mut self,
        action_id: &str,
        level: &str,
        destructive: bool,
        timeout_s: Option<f64>,
    ) -> Result<Confirmation, ConfirmationError> {
        if !matches!(level, "critical_system" | "protected_dir" | "normal") {
            return Err(ConfirmationError::BadLevel(level.to_owned()));
        }
        let mut conf = Confirmation::new(
            action_id,
            level,
            timeout_s.unwrap_or(self.default_timeout_s),
            (self.now_fn)(),
        );
        conf.destructive = destructive;
        if destructive && !self.operator_present {
            conf.queued = true;
        }
        self.items
            .insert(conf.confirmation_id.clone(), conf.clone());
        Ok(conf)
    }

    pub fn resolve(
        &mut self,
        confirmation_id: &str,
        decision: &str,
        decided_by: &str,
    ) -> Result<Confirmation, ConfirmationError> {
        if decision != "approved" && decision != "rejected" {
            return Err(ConfirmationError::BadDecision(decision.to_owned()));
        }
        let conf = self
            .items
            .get_mut(confirmation_id)
            .ok_or_else(|| ConfirmationError::Unknown(confirmation_id.to_owned()))?;
        if conf.decision != "pending" {
            return Ok(conf.clone());
        }
        if conf.queued {
            if decision == "approved" && self.operator_present {
                conf.queued = false;
                conf.decision = "approved".to_owned();
                conf.decided_by = Some(decided_by.to_owned());
            }
        } else {
            conf.decision = decision.to_owned();
            conf.decided_by = Some(decided_by.to_owned());
        }
        Ok(conf.clone())
    }

    pub fn expire(&mut self) -> Vec<Confirmation> {
        let now = (self.now_fn)();
        let mut expired = Vec::new();
        for conf in self.items.values_mut() {
            if conf.decision != "pending" || conf.queued {
                continue;
            }
            if now - conf.created_at >= conf.timeout_s {
                conf.decision = FAIL_SAFE_ON_TIMEOUT.to_owned();
                conf.decided_by = Some("timeout".to_owned());
                expired.push(conf.clone());
            }
        }
        expired
    }

    pub fn executable(&self, confirmation_id: &str) -> bool {
        self.items
            .get(confirmation_id)
            .is_some_and(|conf| conf.decision == "approved" && !conf.queued)
    }

    pub fn try_executable(&self, confirmation_id: &str) -> Result<bool, ConfirmationError> {
        self.items
            .get(confirmation_id)
            .map(|conf| conf.decision == "approved" && !conf.queued)
            .ok_or_else(|| ConfirmationError::Unknown(confirmation_id.to_owned()))
    }

    pub fn executable_uuid(&self, confirmation_id: &Uuid) -> bool {
        self.executable(&confirmation_id.to_string())
    }

    pub fn pending(&self) -> Vec<Confirmation> {
        self.items
            .values()
            .filter(|conf| conf.decision == "pending")
            .cloned()
            .collect()
    }

    pub fn get(&self, confirmation_id: &str) -> Option<&Confirmation> {
        self.items.get(confirmation_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmationError {
    BadLevel(String),
    BadDecision(String),
    Unknown(String),
}

impl std::fmt::Display for ConfirmationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfirmationError::BadLevel(level) => write!(f, "bad confirmation level: {level}"),
            ConfirmationError::BadDecision(decision) => {
                write!(f, "decision must be approved|rejected, got {decision}")
            }
            ConfirmationError::Unknown(id) => write!(f, "unknown confirmation: {id}"),
        }
    }
}

impl std::error::Error for ConfirmationError {}
