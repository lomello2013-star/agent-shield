//! Policy gate — Rust port of `core/gate.py` (E9/E12/PPV, F12b).
//!
//! Containment (reversible actions) is separated from alerting: the alert budget
//! caps noise, while critical findings bypass it. Irreversible actions never
//! appear here.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use crate::types::{Detector, Severity, Verdict};

pub const SEVERITY_ORDER: [&str; 5] = ["info", "low", "medium", "high", "critical"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    InvalidTprFpr,
    InvalidPrevalence,
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::InvalidTprFpr => f.write_str("tpr/fpr must be within 0..1"),
            GateError::InvalidPrevalence => f.write_str("prevalence must be within 0..1"),
        }
    }
}

impl std::error::Error for GateError {}

/// Positive predictive value at a given base rate (E9).
pub fn ppv(tpr: f64, fpr: f64, prevalence: f64) -> Result<f64, GateError> {
    if !(0.0..=1.0).contains(&tpr) || !(0.0..=1.0).contains(&fpr) {
        return Err(GateError::InvalidTprFpr);
    }
    if !(0.0..=1.0).contains(&prevalence) {
        return Err(GateError::InvalidPrevalence);
    }
    let tp = tpr * prevalence;
    let fp = fpr * (1.0 - prevalence);
    Ok(if tp + fp == 0.0 { 0.0 } else { tp / (tp + fp) })
}

#[derive(Clone, Debug, PartialEq)]
pub struct GateDecision {
    pub actions: Vec<String>,
    pub alert: bool,
    pub reason: String,
    pub budget_remaining: usize,
    pub suppressed: bool,
}

type NowFn = Arc<dyn Fn() -> f64 + Send + Sync>;

fn monotonic_now() -> NowFn {
    let origin = Instant::now();
    Arc::new(move || origin.elapsed().as_secs_f64())
}

/// Rolling per-host alert budget.
pub struct AlertBudget {
    pub per_window: usize,
    pub window_s: f64,
    now_fn: NowFn,
    alerts: HashMap<String, VecDeque<f64>>,
}

impl AlertBudget {
    pub fn new(per_window: usize, window_s: f64) -> Self {
        Self::with_clock(per_window, window_s, monotonic_now())
    }

    pub fn with_clock(per_window: usize, window_s: f64, now_fn: NowFn) -> Self {
        Self {
            per_window,
            window_s,
            now_fn,
            alerts: HashMap::new(),
        }
    }

    fn trim(&mut self, host: &str) {
        let cutoff = (self.now_fn)() - self.window_s;
        if let Some(queue) = self.alerts.get_mut(host) {
            while queue.front().is_some_and(|ts| *ts < cutoff) {
                queue.pop_front();
            }
        }
    }

    pub fn remaining(&mut self, host: &str) -> usize {
        self.trim(host);
        let used = self.alerts.get(host).map_or(0, VecDeque::len);
        self.per_window.saturating_sub(used)
    }

    pub fn take(&mut self, host: &str) -> bool {
        if self.remaining(host) == 0 {
            return false;
        }
        self.alerts
            .entry(host.to_owned())
            .or_default()
            .push_back((self.now_fn)());
        true
    }

    pub fn used(&mut self, host: &str) -> usize {
        self.trim(host);
        self.alerts.get(host).map_or(0, VecDeque::len)
    }
}

/// Operator-approved suppressions: (rule_id, target) -> expiry.
pub struct SuppressionList {
    pub ttl_s: f64,
    now_fn: NowFn,
    items: HashMap<(String, String), f64>,
}

impl SuppressionList {
    pub fn new(ttl_s: f64) -> Self {
        Self::with_clock(ttl_s, monotonic_now())
    }

    pub fn with_clock(ttl_s: f64, now_fn: NowFn) -> Self {
        Self {
            ttl_s,
            now_fn,
            items: HashMap::new(),
        }
    }

    pub fn add(&mut self, rule_id: &str, target: &str) {
        self.items.insert(
            (rule_id.to_owned(), target.to_owned()),
            (self.now_fn)() + self.ttl_s,
        );
    }

    pub fn is_suppressed(&mut self, rule_id: &str, target: &str) -> bool {
        let key = (rule_id.to_owned(), target.to_owned());
        let Some(expiry) = self.items.get(&key).copied() else {
            return false;
        };
        if expiry <= (self.now_fn)() {
            self.items.remove(&key);
            return false;
        }
        true
    }

    pub fn count(&mut self) -> usize {
        self.purge();
        self.items.len()
    }

    fn purge(&mut self) {
        let now = (self.now_fn)();
        self.items.retain(|_, expiry| *expiry > now);
    }
}

pub struct PolicyGate {
    pub min_confidence: f64,
    pub budget: AlertBudget,
    pub suppressions: SuppressionList,
    pub actions_by_severity: BTreeMap<String, Vec<String>>,
    pub killed_rules: HashSet<String>,
    pub critical_bypass_budget: bool,
}

impl Default for PolicyGate {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyGate {
    pub fn new() -> Self {
        let mut actions = BTreeMap::new();
        actions.insert(
            "critical".to_owned(),
            vec!["quarantine".to_owned(), "suspend".to_owned()],
        );
        actions.insert("high".to_owned(), vec!["suspend".to_owned()]);
        actions.insert("medium".to_owned(), Vec::new());
        actions.insert("low".to_owned(), Vec::new());
        actions.insert("info".to_owned(), Vec::new());
        Self {
            min_confidence: 0.5,
            budget: AlertBudget::new(1, 14.0 * 24.0 * 3600.0),
            suppressions: SuppressionList::new(7.0 * 24.0 * 3600.0),
            actions_by_severity: actions,
            killed_rules: HashSet::new(),
            critical_bypass_budget: true,
        }
    }

    pub fn with_budget(mut self, budget: AlertBudget) -> Self {
        self.budget = budget;
        self
    }

    pub fn with_min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    pub fn with_critical_bypass(mut self, enabled: bool) -> Self {
        self.critical_bypass_budget = enabled;
        self
    }

    pub fn decide(&mut self, verdict: &Verdict, host_id: &str, target: &str) -> GateDecision {
        let rule_id = verdict.rule_or_model_id();
        if self.killed_rules.contains(&rule_id) {
            return GateDecision {
                actions: Vec::new(),
                alert: false,
                reason: "kill_switch".to_owned(),
                budget_remaining: self.budget.remaining(host_id),
                suppressed: false,
            };
        }
        if self.suppressions.is_suppressed(&rule_id, target) {
            return GateDecision {
                actions: Vec::new(),
                alert: false,
                reason: "suppressed".to_owned(),
                budget_remaining: self.budget.remaining(host_id),
                suppressed: true,
            };
        }
        if verdict.confidence < self.min_confidence {
            return GateDecision {
                actions: Vec::new(),
                alert: false,
                reason: "low_confidence".to_owned(),
                budget_remaining: self.budget.remaining(host_id),
                suppressed: false,
            };
        }
        if verdict.detector != Detector::Rule {
            // ML/behaviour models run in shadow: alert (budgeted) but never contain.
            return GateDecision {
                actions: Vec::new(),
                alert: false,
                reason: "shadow_only".to_owned(),
                budget_remaining: self.budget.remaining(host_id),
                suppressed: false,
            };
        }

        let actions = self
            .actions_by_severity
            .get(verdict.severity.as_str())
            .cloned()
            .unwrap_or_default();
        if actions.is_empty() {
            return GateDecision {
                actions,
                alert: false,
                reason: "observe_only".to_owned(),
                budget_remaining: self.budget.remaining(host_id),
                suppressed: false,
            };
        }
        if verdict.severity == Severity::Critical && self.critical_bypass_budget {
            self.budget.take(host_id);
            return GateDecision {
                actions,
                alert: true,
                reason: "critical_bypass".to_owned(),
                budget_remaining: self.budget.remaining(host_id),
                suppressed: false,
            };
        }
        if self.budget.take(host_id) {
            GateDecision {
                actions,
                alert: true,
                reason: "alert_and_contain".to_owned(),
                budget_remaining: self.budget.remaining(host_id),
                suppressed: false,
            }
        } else {
            GateDecision {
                actions,
                alert: false,
                reason: "contain_without_alert".to_owned(),
                budget_remaining: self.budget.remaining(host_id),
                suppressed: false,
            }
        }
    }

    pub fn approve_for_suppression(&mut self, verdict: &Verdict, target: &str) {
        self.suppressions.add(&verdict.rule_or_model_id(), target);
    }

    pub fn stats(&mut self, host_id: &str) -> Value {
        let mut killed_rules: Vec<&String> = self.killed_rules.iter().collect();
        killed_rules.sort();
        json!({
            "budget_used": self.budget.used(host_id),
            "budget_remaining": self.budget.remaining(host_id),
            "suppressions": self.suppressions.count(),
            "killed_rules": killed_rules,
        })
    }
}
