use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aidf_core::rules::{lint_rules, load_rules, match_condition, rule_matches, Rule, RuleEngine};
use serde_json::{json, Value};
use uuid::Uuid;

fn base_rules() -> Vec<Rule> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rules")
        .join("base.json");
    load_rules(&[path.to_str().unwrap()]).unwrap()
}

fn rule_by_id(id: &str) -> Rule {
    base_rules().into_iter().find(|rule| rule.id == id).unwrap()
}

fn event(
    category: &str,
    action: &str,
    platform: &str,
    actor: Value,
    object: Value,
    platform_data: Value,
) -> Value {
    json!({
        "event_id": Uuid::new_v4().to_string(),
        "trace_id": Uuid::new_v4().to_string(),
        "platform": platform,
        "source": "test",
        "layer": "user",
        "category": category,
        "action": action,
        "actor": actor,
        "object": object,
        "host": {"host_id": "h1"},
        "platform_data": platform_data
    })
}

fn simple_event(category: &str, platform: &str) -> Value {
    event(
        category,
        "start",
        platform,
        json!({"pid": 42, "ppid": 1, "name": "proc", "path": "/usr/bin/proc"}),
        json!({"path": "/tmp/x"}),
        json!({}),
    )
}

#[test]
fn loads_all_rules_and_lints_clean() {
    let rules = base_rules();
    assert_eq!(rules.len(), 30);
    assert!(lint_rules(&rules, None).is_empty());
}

#[test]
fn lsass_access_alerts_critical() {
    let rule = rule_by_id("WIN-LSASS-ACCESS-004");
    let event = event(
        "process.access",
        "open_process",
        "windows",
        json!({"pid": 42, "name": "evil.exe", "path": "C:\\evil.exe"}),
        json!({"type": "process", "path": "C:\\Windows\\System32\\lsass.exe"}),
        json!({}),
    );
    let mut engine = RuleEngine::new(vec![rule]).unwrap();
    let verdicts = engine.evaluate(&event);
    assert!(verdicts.iter().any(|verdict| verdict.rule_id.as_deref()
        == Some("WIN-LSASS-ACCESS-004")
        && verdict.severity == aidf_core::types::Severity::Critical));
}

#[test]
fn powershell_rule_is_conjunctive() {
    let rule = rule_by_id("WIN-PS-ENCODED-002");
    let good = event(
        "process.start",
        "start",
        "windows",
        json!({"pid": 42, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}),
        json!({}),
        json!({"cmdline": "powershell -enc AAAA"}),
    );
    let bad = event(
        "process.start",
        "start",
        "windows",
        json!({"pid": 42, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}),
        json!({}),
        json!({"cmdline": "powershell -file a.ps1"}),
    );
    assert!(rule_matches(&rule, &good));
    assert!(!rule_matches(&rule, &bad));
}

#[test]
fn windowed_rule_fires_only_at_threshold() {
    let rule = rule_by_id("FILE-MASS-WRITE-014");
    let now = Arc::new(Mutex::new(1000.0));
    let clock = Arc::clone(&now);
    let mut engine =
        RuleEngine::with_clock(vec![rule], Arc::new(move || *clock.lock().unwrap())).unwrap();
    let mut verdicts = Vec::new();
    for _ in 0..49 {
        verdicts.extend(engine.evaluate(&simple_event("file.write", "windows")));
    }
    assert!(verdicts.is_empty());
    verdicts.extend(engine.evaluate(&simple_event("file.write", "windows")));
    assert_eq!(verdicts.len(), 1);
}

#[test]
fn window_expires_old_events() {
    let rule = rule_by_id("FILE-MASS-WRITE-014");
    let now = Arc::new(Mutex::new(1000.0));
    let clock = Arc::clone(&now);
    let mut engine =
        RuleEngine::with_clock(vec![rule], Arc::new(move || *clock.lock().unwrap())).unwrap();
    for _ in 0..30 {
        engine.evaluate(&simple_event("file.write", "windows"));
    }
    *now.lock().unwrap() += 20.0;
    for _ in 0..30 {
        engine.evaluate(&simple_event("file.write", "windows"));
    }
    assert_eq!(
        engine
            .counts()
            .get("FILE-MASS-WRITE-014")
            .copied()
            .unwrap_or(0),
        0
    );
}

#[test]
fn correlation_fires_when_both_seen_in_window() {
    let rule = correlation_rule("actor.pid");
    let now = Arc::new(Mutex::new(1000.0));
    let clock = Arc::clone(&now);
    let mut engine =
        RuleEngine::with_clock(vec![rule], Arc::new(move || *clock.lock().unwrap())).unwrap();
    let first = event(
        "memory.access",
        "mprotect_exec",
        "linux",
        json!({"pid": 42, "ppid": 1}),
        json!({}),
        json!({"anon": true}),
    );
    let second = event(
        "memory.access",
        "process_vm_writev",
        "linux",
        json!({"pid": 42, "ppid": 1}),
        json!({}),
        json!({}),
    );
    assert!(engine.evaluate(&first).is_empty());
    let verdicts = engine.evaluate(&second);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].reason_code, "mprotect_after_injection");
}

#[test]
fn correlation_requires_window_and_same_group() {
    let rule = correlation_rule("actor.pid");
    let now = Arc::new(Mutex::new(1000.0));
    let clock = Arc::clone(&now);
    let mut engine =
        RuleEngine::with_clock(vec![rule], Arc::new(move || *clock.lock().unwrap())).unwrap();
    let first = event(
        "memory.access",
        "mprotect_exec",
        "linux",
        json!({"pid": 1}),
        json!({}),
        json!({"anon": true}),
    );
    engine.evaluate(&first);
    *now.lock().unwrap() += 6.0;
    let late = event(
        "memory.access",
        "process_vm_writev",
        "linux",
        json!({"pid": 1}),
        json!({}),
        json!({}),
    );
    assert!(engine.evaluate(&late).is_empty());

    let other = event(
        "memory.access",
        "process_vm_writev",
        "linux",
        json!({"pid": 2}),
        json!({}),
        json!({}),
    );
    assert!(engine.evaluate(&other).is_empty());
}

#[test]
fn negative_operators() {
    assert!(match_condition(
        Some(&json!("/tmp/x")),
        &json!({"not_regex": "^/(usr|bin)/"})
    ));
    assert!(!match_condition(
        Some(&json!("/usr/bin/x")),
        &json!({"not_regex": "^/(usr|bin)/"})
    ));
    assert!(match_condition(
        Some(&json!("/tmp/x")),
        &json!({"not_startswith": "/usr"})
    ));
    assert!(match_condition(
        Some(&json!("hello")),
        &json!({"not_contains": "evil"})
    ));
    assert!(!match_condition(None, &json!({"not_regex": "x"})));
}

#[test]
fn engine_rejects_invalid_rules() {
    let bad: Rule = serde_json::from_value(json!({
        "id": "R-1",
        "title": "t",
        "severity": "high",
        "technique": "T1059",
        "layer": "L2",
        "match": {"nope": 1},
        "reason_code": "r"
    }))
    .unwrap();
    assert!(RuleEngine::new(vec![bad]).is_err());
}

#[test]
fn lint_catches_duplicates_and_bad_fields() {
    let good: Rule = serde_json::from_value(json!({
        "id": "R-1", "title": "t", "severity": "high", "technique": "T1059",
        "layer": "L2", "match": {"category": "process.start"}, "reason_code": "r"
    }))
    .unwrap();
    let mut duplicate = good.clone();
    duplicate.title = "t2".to_owned();
    assert!(lint_rules(&[good.clone(), duplicate], None)
        .iter()
        .any(|problem| problem.contains("duplicate")));

    let mut bad_field = good.clone();
    bad_field.id = "R-2".to_owned();
    bad_field.match_ = json!({"actor.nonexistent": "x"});
    assert!(lint_rules(&[bad_field], None)
        .iter()
        .any(|problem| problem.contains("unknown field")));

    let mut bad_severity = good.clone();
    bad_severity.id = "R-3".to_owned();
    bad_severity.severity = "urgent".to_owned();
    assert!(lint_rules(&[bad_severity], None)
        .iter()
        .any(|problem| problem.contains("severity")));
}

#[test]
fn lint_catches_unknown_technique() {
    let rule: Rule = serde_json::from_value(json!({
        "id": "R-6", "title": "t", "severity": "high", "technique": "T9999",
        "layer": "L2", "match": {"category": "process.start"}, "reason_code": "r"
    }))
    .unwrap();
    let known: HashSet<String> = ["T1059".to_owned()].into_iter().collect();
    assert!(lint_rules(&[rule], Some(&known))
        .iter()
        .any(|problem| problem.contains("not in coverage matrix")));
}

#[test]
fn disabled_rule_not_evaluated() {
    let mut rule = rule_by_id("WIN-LOG-CLEAR-008");
    rule.enabled = false;
    let mut engine = RuleEngine::new(vec![rule]).unwrap();
    assert!(engine
        .evaluate(&simple_event("log.tamper", "windows"))
        .is_empty());
}

fn correlation_rule(group_by: &str) -> Rule {
    serde_json::from_value(json!({
        "id": "LINUX-EXEC-CORR-108",
        "title": "mprotect EXEC after a cross-process memory write",
        "severity": "high",
        "technique": "T1055",
        "layer": "L3",
        "match": {},
        "reason_code": "mprotect_after_injection",
        "correlate": {
            "window_sec": 5,
            "group_by": group_by,
            "require": [
                {"category": "memory.access", "action": "mprotect_exec", "platform_data.anon": true},
                {"category": "memory.access", "action": {"regex": "(?i)(vm_write|ptrace|proc_mem)"}}
            ]
        }
    }))
    .unwrap()
}

#[test]
fn counts_are_exposed_by_rule_id() {
    let rule = rule_by_id("WIN-LSASS-ACCESS-004");
    let event = event(
        "process.access",
        "open_process",
        "windows",
        json!({"pid": 42}),
        json!({"path": "C:\\Windows\\System32\\lsass.exe"}),
        json!({}),
    );
    let mut engine = RuleEngine::new(vec![rule]).unwrap();
    engine.evaluate(&event);
    let counts: HashMap<String, u64> = engine.counts();
    assert_eq!(counts.get("WIN-LSASS-ACCESS-004"), Some(&1));
}

