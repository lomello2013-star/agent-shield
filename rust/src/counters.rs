//! Loss counters — Rust port of `core/counters.py`.
//!
//! Every loss path must call [`LossCounters::inc`]; a non-zero `lost` or
//! `overflow` is an incident (R8). The optional callback fires only for those
//! two names after the counter has been updated.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

pub const LOST: &str = "lost";
pub const OVERFLOW: &str = "overflow";
pub const BACKLOG: &str = "backlog";
pub const SPILLED: &str = "spilled";
pub const EVICTED: &str = "evicted";
pub const AGGREGATED: &str = "aggregated";
pub const REPLAYED: &str = "replayed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterError {
    NegativeDelta,
}

impl fmt::Display for CounterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CounterError::NegativeDelta => f.write_str("counter delta must be non-negative"),
        }
    }
}

impl std::error::Error for CounterError {}

type LossCallback = Arc<dyn Fn(&str, i64) + Send + Sync>;

/// Thread-safe counters plus an alert callback on any loss.
pub struct LossCounters {
    counts: Mutex<BTreeMap<String, i64>>,
    on_loss: Option<LossCallback>,
}

impl Default for LossCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl LossCounters {
    pub fn new() -> Self {
        Self {
            counts: Mutex::new(BTreeMap::new()),
            on_loss: None,
        }
    }

    /// Build counters with a callback invoked for `LOST`/`OVERFLOW` only.
    pub fn with_on_loss<F>(on_loss: F) -> Self
    where
        F: Fn(&str, i64) + Send + Sync + 'static,
    {
        Self {
            counts: Mutex::new(BTreeMap::new()),
            on_loss: Some(Arc::new(on_loss)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, i64>> {
        // A poisoned lock must not hide loss accounting; recover the data.
        self.counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Increment `name` by `n`. Negative deltas are rejected (Python parity).
    pub fn inc(&self, name: &str, n: i64) -> Result<i64, CounterError> {
        if n < 0 {
            return Err(CounterError::NegativeDelta);
        }
        let value = {
            let mut counts = self.lock();
            let entry = counts.entry(name.to_string()).or_insert(0);
            *entry += n;
            *entry
        };
        if n > 0 && (name == LOST || name == OVERFLOW) {
            if let Some(callback) = &self.on_loss {
                callback(name, n);
            }
        }
        Ok(value)
    }

    /// Convenience wrapper for `inc(name, 1)`.
    pub fn inc_one(&self, name: &str) -> Result<i64, CounterError> {
        self.inc(name, 1)
    }

    pub fn get(&self, name: &str) -> i64 {
        self.lock().get(name).copied().unwrap_or(0)
    }

    pub fn set(&self, name: &str, value: i64) {
        self.lock().insert(name.to_string(), value);
    }

    /// Deterministic snapshot (keys sorted by `BTreeMap`).
    pub fn snapshot(&self) -> BTreeMap<String, i64> {
        self.lock().clone()
    }

    pub fn loss_total(&self) -> i64 {
        let counts = self.lock();
        counts.get(LOST).copied().unwrap_or(0) + counts.get(OVERFLOW).copied().unwrap_or(0)
    }

    pub fn is_clean(&self) -> bool {
        self.loss_total() == 0
    }
}
