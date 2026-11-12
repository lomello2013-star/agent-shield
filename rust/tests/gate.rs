use std::sync::{Arc, Mutex};

use aidf_core::gate::{ppv, AlertBudget, GateError, PolicyGate, SuppressionList};
use aidf_core::types::{Detector, Severity, Verdict};

struct FakeClock {
    now: Arc<Mutex<f64>>,
}

impl FakeClock {
    fn new() -> (Self, Arc<Mutex<f64>>) {
        let now = Arc::new(Mutex::new(1000.0));
        (
            Self {
                now: Arc::clone(&now),
            },
            now,
        )
    }

    fn now_fn(&self) -> Arc<dyn Fn() -> f64 + Send + Sync> {
        let now = Arc::clone(&self.now);
        Arc::new(move || *now.lock().unwrap())
    }
}

fn verdict(severity: Severity, confidence: f64, rule_id: &str) -> Verdict {
    Verdict::new(
        Detector::Rule,
        "windows",
        confidence,
        severity,
        Some(rule_id),
        None,
        "rc",
        "rt",
    )
}

#[test]
fn ppv_matches_formula() {
    assert_eq!(ppv(1.0, 0.0, 0.001).unwrap(), 1.0);
    assert_eq!(ppv(0.0, 1.0, 0.001).unwrap(), 0.0);
    let value = ppv(0.87, 0.01, 0.001).unwrap();
    assert!(value > 0.07 && value < 0.09);
}

#[test]
fn ppv_rejects_bad_ranges() {
    assert_eq!(ppv(1.5, 0.0, 0.001), Err(GateError::InvalidTprFpr));
    assert_eq!(ppv(0.9, 0.1, 2.0), Err(GateError::InvalidPrevalence));
}

#[test]
fn budget_limits_alerts_in_window() {
    let (fake, now) = FakeClock::new();
    let mut budget = AlertBudget::with_clock(1, 100.0, fake.now_fn());
    assert!(budget.take("h1"));
    assert!(!budget.take("h1"));
    assert_eq!(budget.used("h1"), 1);
    *now.lock().unwrap() += 101.0;
    assert!(budget.take("h1"));
}

#[test]
fn budget_is_per_host() {
    let mut budget = AlertBudget::new(1, 100.0);
    assert!(budget.take("h1"));
    assert!(budget.take("h2"));
}

#[test]
fn suppression_expires() {
    let (fake, now) = FakeClock::new();
    let mut suppressions = SuppressionList::with_clock(50.0, fake.now_fn());
    suppressions.add("R-1", "pid:42");
    assert!(suppressions.is_suppressed("R-1", "pid:42"));
    *now.lock().unwrap() += 51.0;
    assert!(!suppressions.is_suppressed("R-1", "pid:42"));
    assert_eq!(suppressions.count(), 0);
}

#[test]
fn critical_verdict_proposes_reversible_actions_and_alerts() {
    let mut gate = PolicyGate::new();
    let decision = gate.decide(&verdict(Severity::Critical, 1.0, "R-1"), "h1", "pid:1");
    assert_eq!(
        decision.actions,
        vec!["quarantine".to_owned(), "suspend".to_owned()]
    );
    assert!(decision.alert);
    assert_eq!(decision.reason, "critical_bypass");
}

#[test]
fn medium_severity_is_observe_only() {
    let decision = PolicyGate::new().decide(&verdict(Severity::Medium, 1.0, "R-1"), "h1", "pid:1");
    assert!(decision.actions.is_empty());
    assert!(!decision.alert);
    assert_eq!(decision.reason, "observe_only");
}

#[test]
fn high_severity_suspends_without_quarantine() {
    let decision = PolicyGate::new().decide(&verdict(Severity::High, 1.0, "R-1"), "h1", "pid:1");
    assert_eq!(decision.actions, vec!["suspend".to_owned()]);
}

#[test]
fn low_confidence_blocks_actions() {
    let mut gate = PolicyGate::new().with_min_confidence(0.8);
    let decision = gate.decide(&verdict(Severity::Critical, 0.4, "R-1"), "h1", "");
    assert!(decision.actions.is_empty());
    assert_eq!(decision.reason, "low_confidence");
}

#[test]
fn budget_exhaustion_contains_without_alert() {
    let mut gate = PolicyGate::new().with_budget(AlertBudget::new(1, 1000.0));
    let first = gate.decide(&verdict(Severity::High, 1.0, "R-1"), "h1", "pid:1");
    let second = gate.decide(&verdict(Severity::High, 1.0, "R-1"), "h1", "pid:2");
    assert!(first.alert);
    assert!(!second.alert);
    assert_eq!(second.reason, "contain_without_alert");
    assert_eq!(second.actions, vec!["suspend".to_owned()]);
}

#[test]
fn suppression_prevents_repeat_alerts() {
    let mut gate = PolicyGate::new();
    gate.approve_for_suppression(&verdict(Severity::High, 1.0, "R-9"), "pid:7");
    let decision = gate.decide(&verdict(Severity::High, 1.0, "R-9"), "h1", "pid:7");
    assert!(!decision.alert);
    assert!(decision.suppressed);
    assert!(decision.actions.is_empty());
}

#[test]
fn kill_switch_drops_rule_entirely() {
    let mut gate = PolicyGate::new();
    gate.killed_rules.insert("R-1".to_owned());
    let decision = gate.decide(&verdict(Severity::Critical, 1.0, "R-1"), "h1", "");
    assert!(decision.actions.is_empty());
    assert_eq!(decision.reason, "kill_switch");
}

#[test]
fn model_verdicts_are_shadow_only() {
    let model = Verdict::new(
        Detector::FileModel,
        "windows",
        0.99,
        Severity::Critical,
        None,
        Some("pe"),
        "ml",
        "shadow",
    );
    let decision = PolicyGate::new().decide(&model, "h1", "C:\\x.exe");
    assert!(decision.actions.is_empty());
    assert_eq!(decision.reason, "shadow_only");
}

#[test]
fn gate_stats_report_budget_and_suppressions() {
    let mut gate = PolicyGate::new().with_budget(AlertBudget::new(2, 1000.0));
    gate.decide(&verdict(Severity::High, 1.0, "R-1"), "h1", "pid:1");
    gate.approve_for_suppression(&verdict(Severity::High, 1.0, "R-2"), "pid:2");
    let stats = gate.stats("h1");
    assert_eq!(stats["budget_used"].as_u64(), Some(1));
    assert_eq!(stats["budget_remaining"].as_u64(), Some(1));
    assert_eq!(stats["suppressions"].as_u64(), Some(1));
}

#[test]
fn low_severity_signal_never_alerts() {
    let mut gate = PolicyGate::new().with_budget(AlertBudget::new(10, 100.0));
    let decision = gate.decide(
        &verdict(Severity::Low, 1.0, "LINUX-EXEC-CORR-109"),
        "h1",
        "",
    );
    assert!(!decision.alert);
    assert!(decision.actions.is_empty());
    assert_eq!(decision.reason, "observe_only");
}

#[test]
fn high_severity_provenance_rule_alerts() {
    let mut gate = PolicyGate::new().with_budget(AlertBudget::new(10, 100.0));
    let decision = gate.decide(
        &verdict(Severity::High, 1.0, "LINUX-EXEC-CORR-110"),
        "h1",
        "",
    );
    assert!(decision.alert);
    assert_eq!(decision.actions, vec!["suspend".to_owned()]);
}

#[test]
fn critical_alerts_even_when_budget_is_spent() {
    let (fake, _) = FakeClock::new();
    let mut gate = PolicyGate::new().with_budget(AlertBudget::with_clock(1, 1000.0, fake.now_fn()));
    let first = gate.decide(&verdict(Severity::High, 1.0, "R-1"), "h1", "");
    assert!(first.alert);
    let critical = gate.decide(
        &verdict(Severity::Critical, 1.0, "FILE-CANARY-015"),
        "h1",
        "",
    );
    assert!(critical.alert);
    assert_eq!(critical.reason, "critical_bypass");
    assert!(critical.actions.contains(&"quarantine".to_owned()));
}

#[test]
fn high_is_still_budgeted_after_critical() {
    let (fake, _) = FakeClock::new();
    let mut gate = PolicyGate::new().with_budget(AlertBudget::with_clock(1, 1000.0, fake.now_fn()));
    gate.decide(&verdict(Severity::Critical, 1.0, "C-1"), "h1", "");
    let decision = gate.decide(&verdict(Severity::High, 1.0, "H-1"), "h1", "");
    assert!(!decision.alert);
    assert_eq!(decision.actions, vec!["suspend".to_owned()]);
}

#[test]
fn critical_bypass_can_be_disabled() {
    let (fake, _) = FakeClock::new();
    let mut gate = PolicyGate::new()
        .with_budget(AlertBudget::with_clock(1, 1000.0, fake.now_fn()))
        .with_critical_bypass(false);
    gate.decide(&verdict(Severity::High, 1.0, "R-1"), "h1", "");
    let decision = gate.decide(&verdict(Severity::Critical, 1.0, "C-1"), "h1", "");
    assert!(!decision.alert);
}
