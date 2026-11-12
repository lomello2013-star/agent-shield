//! Minimal v3.0 types needed by the ported modules.
//!
//! The Python implementation uses pydantic models; the Rust port keeps the same
//! field semantics but not the full validation surface (that lives in the Python
//! reference until the whole daemon is ported).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    Rule,
    FileModel,
    BehaviorModel,
    MemoryModel,
    NetModel,
}

impl Detector {
    pub fn as_str(self) -> &'static str {
        match self {
            Detector::Rule => "rule",
            Detector::FileModel => "file_model",
            Detector::BehaviorModel => "behavior_model",
            Detector::MemoryModel => "memory_model",
            Detector::NetModel => "net_model",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verdict {
    pub verdict_id: Uuid,
    pub trace_id: Uuid,
    pub event_id: Uuid,
    pub detector: Detector,
    pub rule_id: Option<String>,
    pub model_id: Option<String>,
    pub model_version: Option<String>,
    pub platform: String,
    pub confidence: f64,
    pub severity: Severity,
    pub reason_code: String,
    pub reason_text: String,
}

impl Verdict {
    /// Test/helper constructor with fresh IDs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        detector: Detector,
        platform: &str,
        confidence: f64,
        severity: Severity,
        rule_id: Option<&str>,
        model_id: Option<&str>,
        reason_code: &str,
        reason_text: &str,
    ) -> Self {
        Self {
            verdict_id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
            detector,
            rule_id: rule_id.map(str::to_owned),
            model_id: model_id.map(str::to_owned),
            model_version: None,
            platform: platform.to_owned(),
            confidence,
            severity,
            reason_code: reason_code.to_owned(),
            reason_text: reason_text.to_owned(),
        }
    }

    /// Identifier used by the gate for kill-switch/suppression keys.
    pub fn rule_or_model_id(&self) -> String {
        self.rule_id
            .clone()
            .or_else(|| self.model_id.clone())
            .unwrap_or_default()
    }
}
