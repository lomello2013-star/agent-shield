//! Deterministic rules engine — Rust port of `core/rules.py`.
//!
//! Rules are data (JSON), never code. Matching is a conjunction of field
//! conditions; windowed rules count events per group; correlation rules require
//! several conditions for the same entity inside a window. The engine never
//! executes anything; it only emits `Verdict`s.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::types::{Detector, Severity, Verdict};

pub const KNOWN_OPERATORS: [&str; 13] = [
    "regex",
    "in",
    "startswith",
    "endswith",
    "contains",
    "gt",
    "lt",
    "gte",
    "lte",
    "equals",
    "not_regex",
    "not_startswith",
    "not_contains",
];

pub const MAX_REGEX_LEN: usize = 200;
pub const MAX_REGEX_INPUT: usize = 512;

pub const ALLOWED_FIELDS: [&str; 35] = [
    "platform",
    "source",
    "layer",
    "category",
    "action",
    "actor.pid",
    "actor.name",
    "actor.path",
    "actor.cmdline_redacted",
    "actor.signature",
    "actor.sha256",
    "actor.uid",
    "actor.sid",
    "actor.session",
    "actor.ppid",
    "object.type",
    "object.path",
    "object.sha256",
    "object.ip",
    "object.port",
    "object.proto",
    "user.name",
    "user.domain",
    "host.host_id",
    "host.os",
    "host.version",
    "host.arch",
    "integrity.level",
    "integrity.verified",
    "kernel_meta.irql",
    "kernel_meta.callback_type",
    "kernel_meta.trust",
    "platform_data",
    "host.kernel",
    "raw_ref",
];

fn allowed_field(path: &str) -> bool {
    ALLOWED_FIELDS.contains(&path) || path.starts_with("platform_data.")
}

fn default_group_by() -> String {
    "host.host_id".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub technique: String,
    pub layer: String,
    #[serde(rename = "match", default)]
    pub match_: Value,
    pub reason_code: String,
    #[serde(default)]
    pub prevention: bool,
    #[serde(default)]
    pub window_sec: Option<f64>,
    #[serde(default)]
    pub threshold: Option<i64>,
    #[serde(default = "default_group_by")]
    pub group_by: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub correlate: Option<Value>,
}

fn default_true() -> bool {
    true
}

impl Rule {
    pub fn windowed(&self) -> bool {
        self.window_sec.is_some() || self.threshold.is_some()
    }

    pub fn correlated(&self) -> bool {
        self.correlate.is_some()
    }
}

/// Load rules from one or more JSON files (array or `{"rules": [...]}`).
pub fn load_rules(paths: &[&str]) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
        let payload: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|error| format!("{path}: {error}"))?;
        let items = payload
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| payload.as_array().cloned())
            .ok_or_else(|| format!("{path}: expected an array or an object with rules"))?;
        for item in items {
            rules.push(
                serde_json::from_value(item)
                    .map_err(|error| format!("{path}: invalid rule: {error}"))?,
            );
        }
    }
    Ok(rules)
}

fn get_path<'a>(payload: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = payload;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => "None".to_owned(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn value_as_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(_), Value::Number(_)) => value_as_f64(left) == value_as_f64(right),
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Null, Value::Null) => true,
        _ => left == right,
    }
}

static REGEX_CACHE: LazyLock<Mutex<HashMap<String, Option<FancyRegex>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn regex_search(pattern: &str, value: &str) -> bool {
    let input: String = value.chars().take(MAX_REGEX_INPUT).collect();
    let mut cache = REGEX_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let regex = cache
        .entry(pattern.to_owned())
        .or_insert_with(|| FancyRegex::new(pattern).ok());
    regex
        .as_ref()
        .map(|regex| regex.is_match(&input).unwrap_or(false))
        .unwrap_or(false)
}

/// Match one condition. `actual` is `None` when the field is missing.
pub fn match_condition(actual: Option<&Value>, condition: &Value) -> bool {
    match condition {
        Value::Object(operators) => {
            for (operator, operand) in operators {
                let ok = match operator.as_str() {
                    "regex" => actual.is_some_and(|value| {
                        regex_search(&value_to_string(operand), &value_to_string(value))
                    }),
                    "in" => {
                        let Some(list) = operand.as_array() else {
                            return false;
                        };
                        actual
                            .is_some_and(|value| list.iter().any(|item| values_equal(value, item)))
                    }
                    "startswith" => actual.is_some_and(|value| {
                        value_to_string(value)
                            .to_lowercase()
                            .starts_with(&value_to_string(operand).to_lowercase())
                    }),
                    "endswith" => actual.is_some_and(|value| {
                        value_to_string(value)
                            .to_lowercase()
                            .ends_with(&value_to_string(operand).to_lowercase())
                    }),
                    "contains" => actual.is_some_and(|value| {
                        value_to_string(value)
                            .to_lowercase()
                            .contains(&value_to_string(operand).to_lowercase())
                    }),
                    "not_regex" => actual.is_some_and(|value| {
                        !regex_search(&value_to_string(operand), &value_to_string(value))
                    }),
                    "not_startswith" => actual.is_some_and(|value| {
                        !value_to_string(value)
                            .to_lowercase()
                            .starts_with(&value_to_string(operand).to_lowercase())
                    }),
                    "not_contains" => actual.is_some_and(|value| {
                        !value_to_string(value)
                            .to_lowercase()
                            .contains(&value_to_string(operand).to_lowercase())
                    }),
                    "gt" => actual
                        .and_then(value_as_f64)
                        .zip(value_as_f64(operand))
                        .is_some_and(|(a, b)| a > b),
                    "lt" => actual
                        .and_then(value_as_f64)
                        .zip(value_as_f64(operand))
                        .is_some_and(|(a, b)| a < b),
                    "gte" => actual
                        .and_then(value_as_f64)
                        .zip(value_as_f64(operand))
                        .is_some_and(|(a, b)| a >= b),
                    "lte" => actual
                        .and_then(value_as_f64)
                        .zip(value_as_f64(operand))
                        .is_some_and(|(a, b)| a <= b),
                    "equals" => actual.is_some_and(|value| values_equal(value, operand)),
                    _ => false,
                };
                if !ok {
                    return false;
                }
            }
            true
        }
        Value::Array(items) => {
            actual.is_some_and(|value| items.iter().any(|item| values_equal(value, item)))
        }
        Value::Bool(expected) => actual.is_some_and(|value| value.as_bool() == Some(*expected)),
        _ => actual.is_some_and(|value| {
            value_to_string(value).to_lowercase() == value_to_string(condition).to_lowercase()
        }),
    }
}

pub fn conditions_match(conditions: &Value, payload: &Value) -> bool {
    let Some(conditions) = conditions.as_object() else {
        return false;
    };
    conditions
        .iter()
        .all(|(path, condition)| match_condition(get_path(payload, path), condition))
}

pub fn rule_matches(rule: &Rule, payload: &Value) -> bool {
    conditions_match(&rule.match_, payload)
}

fn lint_condition(rule_id: &str, condition: &Value, problems: &mut Vec<String>) {
    let Some(operators) = condition.as_object() else {
        return;
    };
    let nested = Regex::new(r"\([^)]*[+*][^)]*\)[+*]").expect("static regex");
    for (operator, operand) in operators {
        if !KNOWN_OPERATORS.contains(&operator.as_str()) {
            problems.push(format!("{rule_id}: unknown operator {operator:?}"));
        }
        if operator == "regex" || operator == "not_regex" {
            let pattern = value_to_string(operand);
            if pattern.chars().count() > MAX_REGEX_LEN {
                problems.push(format!("{rule_id}: regex too long (>{MAX_REGEX_LEN})"));
            }
            if nested.is_match(&pattern) {
                problems.push(format!(
                    "{rule_id}: nested quantifier in regex (ReDoS shape)"
                ));
            }
            if FancyRegex::new(&pattern).is_err() {
                problems.push(format!("{rule_id}: bad regex: {pattern}"));
            }
        }
    }
}

/// Validate rules; returns a list of problems (empty == clean).
pub fn lint_rules(rules: &[Rule], known_techniques: Option<&HashSet<String>>) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = HashSet::new();
    let id_re = Regex::new(r"^[A-Z0-9][A-Z0-9\-_.]{4,63}$").expect("static regex");
    let technique_re = Regex::new(r"^T\d{4}(\.\d{3})?$").expect("static regex");

    for rule in rules {
        if !id_re.is_match(&rule.id) {
            problems.push(format!("{:?}: id must be UPPER-case, 5..64 chars", rule.id));
        }
        if !seen.insert(rule.id.clone()) {
            problems.push(format!("{}: duplicate id", rule.id));
        }
        if Severity::parse(&rule.severity).is_none() {
            problems.push(format!("{}: bad severity {:?}", rule.id, rule.severity));
        }
        if !technique_re.is_match(&rule.technique) {
            problems.push(format!(
                "{}: bad ATT&CK technique {:?}",
                rule.id, rule.technique
            ));
        }
        if let Some(known) = known_techniques {
            if !known.contains(&rule.technique) {
                problems.push(format!(
                    "{}: technique {} not in coverage matrix",
                    rule.id, rule.technique
                ));
            }
        }
        if rule.title.trim().is_empty() {
            problems.push(format!("{}: empty title", rule.id));
        }
        if rule
            .match_
            .as_object()
            .is_none_or(|object| object.is_empty())
            && !rule.correlated()
        {
            problems.push(format!("{}: empty match", rule.id));
        }
        if let Some(conditions) = rule.match_.as_object() {
            for (path, condition) in conditions {
                if !allowed_field(path) && path != "platform_data" {
                    problems.push(format!("{}: unknown field {path:?}", rule.id));
                }
                lint_condition(&rule.id, condition, &mut problems);
            }
        }
        if let Some(correlate) = &rule.correlate {
            let Some(spec) = correlate.as_object() else {
                problems.push(format!("{}: correlate must be an object", rule.id));
                continue;
            };
            match spec.get("require").and_then(Value::as_array) {
                Some(require)
                    if require.len() >= 2
                        && require.iter().all(|item| {
                            item.as_object().is_some_and(|object| !object.is_empty())
                        }) =>
                {
                    for item in require {
                        if let Some(conditions) = item.as_object() {
                            for (path, condition) in conditions {
                                if !allowed_field(path) && path != "platform_data" {
                                    problems.push(format!(
                                        "{}: unknown field {path:?} in correlate",
                                        rule.id
                                    ));
                                }
                                lint_condition(&rule.id, condition, &mut problems);
                            }
                        }
                    }
                }
                _ => problems.push(format!(
                    "{}: correlate.require needs >= 2 non-empty objects",
                    rule.id
                )),
            }
            if !spec
                .get("window_sec")
                .and_then(Value::as_f64)
                .is_some_and(|window| window > 0.0)
            {
                problems.push(format!("{}: correlate.window_sec must be > 0", rule.id));
            }
            let group_by = spec
                .get("group_by")
                .and_then(Value::as_str)
                .unwrap_or("actor.pid");
            if group_by != "process_tree" && !allowed_field(group_by) {
                problems.push(format!("{}: unknown correlate.group_by", rule.id));
            }
        }
        if rule.windowed() {
            if rule.window_sec.is_none() || rule.threshold.is_none() {
                problems.push(format!(
                    "{}: windowed rule needs both window_sec and threshold",
                    rule.id
                ));
            } else if rule.window_sec.is_some_and(|window| window <= 0.0)
                || rule.threshold.is_some_and(|threshold| threshold < 2)
            {
                problems.push(format!("{}: window/threshold out of range", rule.id));
            }
            if !allowed_field(&rule.group_by) {
                problems.push(format!("{}: unknown group_by {:?}", rule.id, rule.group_by));
            }
        }
    }
    problems
}

type NowFn = Arc<dyn Fn() -> f64 + Send + Sync>;

pub struct RuleEngine {
    rules: Vec<Rule>,
    now_fn: NowFn,
    windows: HashMap<(String, String), VecDeque<f64>>,
    counts: HashMap<String, u64>,
    corr: HashMap<(String, String), HashMap<usize, f64>>,
    parents: HashMap<i64, i64>,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>) -> Result<Self, Vec<String>> {
        let origin = Instant::now();
        Self::with_clock(rules, Arc::new(move || origin.elapsed().as_secs_f64()))
    }

    pub fn with_clock(rules: Vec<Rule>, now_fn: NowFn) -> Result<Self, Vec<String>> {
        let rules: Vec<Rule> = rules.into_iter().filter(|rule| rule.enabled).collect();
        let problems = lint_rules(&rules, None);
        if !problems.is_empty() {
            return Err(problems);
        }
        Ok(Self {
            rules,
            now_fn,
            windows: HashMap::new(),
            counts: HashMap::new(),
            corr: HashMap::new(),
            parents: HashMap::new(),
        })
    }

    /// Evaluate one Event (as JSON); returns verdicts (usually zero or one).
    pub fn evaluate(&mut self, event: &Value) -> Vec<Verdict> {
        let now = (self.now_fn)();
        self.remember_parent(event);
        let rules = self.rules.clone();
        let mut out = Vec::new();
        for rule in &rules {
            if rule.correlated() {
                if !self.correlation_hit(rule, event, now) {
                    continue;
                }
            } else if !rule_matches(rule, event) {
                continue;
            } else if rule.windowed() {
                let group =
                    value_to_string(get_path(event, &rule.group_by).unwrap_or(&Value::Null));
                let key = (rule.id.clone(), group);
                let bucket = self.windows.entry(key).or_default();
                bucket.push_back(now);
                let window = rule.window_sec.unwrap_or(0.0);
                while bucket.front().is_some_and(|ts| now - *ts > window) {
                    bucket.pop_front();
                }
                if bucket.len() < rule.threshold.unwrap_or(0) as usize {
                    continue;
                }
                bucket.clear();
            }
            *self.counts.entry(rule.id.clone()).or_insert(0) += 1;
            let severity = Severity::parse(&rule.severity).unwrap_or(Severity::Low);
            let platform = event
                .get("platform")
                .and_then(Value::as_str)
                .unwrap_or("windows");
            let mut verdict = Verdict::new(
                Detector::Rule,
                platform,
                1.0,
                severity,
                Some(&rule.id),
                None,
                &rule.reason_code,
                &rule.title,
            );
            verdict.trace_id = event_uuid(event, "trace_id");
            verdict.event_id = event_uuid(event, "event_id");
            out.push(verdict);
        }
        out
    }

    fn remember_parent(&mut self, payload: &Value) {
        let pid = get_path(payload, "actor.pid").and_then(Value::as_i64);
        let ppid = get_path(payload, "actor.ppid").and_then(Value::as_i64);
        if let (Some(pid), Some(ppid)) = (pid, ppid) {
            if ppid > 0 && pid != ppid {
                self.parents.insert(pid, ppid);
            }
        }
    }

    fn root_pid(&self, pid: Option<i64>) -> String {
        let mut current = pid;
        for _ in 0..8 {
            let Some(value) = current else {
                break;
            };
            let Some(parent) = self.parents.get(&value) else {
                break;
            };
            if *parent == value {
                break;
            }
            current = Some(*parent);
        }
        current.map_or_else(|| "None".to_owned(), |value| value.to_string())
    }

    fn group_key(&self, rule: &Rule, payload: &Value) -> String {
        let mode = rule
            .correlate
            .as_ref()
            .and_then(|spec| spec.get("group_by"))
            .and_then(Value::as_str)
            .unwrap_or("actor.pid");
        if mode == "process_tree" {
            return format!(
                "tree:{}",
                self.root_pid(get_path(payload, "actor.pid").and_then(Value::as_i64))
            );
        }
        get_path(payload, mode)
            .map(value_to_string)
            .unwrap_or_else(|| "None".to_owned())
    }

    fn correlation_hit(&mut self, rule: &Rule, payload: &Value, now: f64) -> bool {
        let Some(spec) = rule.correlate.as_ref().and_then(Value::as_object) else {
            return false;
        };
        let Some(require) = spec.get("require").and_then(Value::as_array) else {
            return false;
        };
        let window = spec
            .get("window_sec")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let group = self.group_key(rule, payload);
        let state = self.corr.entry((rule.id.clone(), group)).or_default();
        for (index, conditions) in require.iter().enumerate() {
            if conditions_match(conditions, payload) {
                state.insert(index, now);
            }
        }
        state.retain(|_, timestamp| now - *timestamp <= window);
        if state.len() == require.len() {
            state.clear();
            true
        } else {
            false
        }
    }

    pub fn counts(&self) -> HashMap<String, u64> {
        self.counts.clone()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// Helpers for tests: read `trace_id`/`event_id` if present.
pub fn event_uuid(payload: &Value, key: &str) -> Uuid {
    payload
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(Uuid::new_v4)
}
