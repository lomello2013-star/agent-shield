//! Heartbeat + synthetic probe per telemetry source — Rust port of
//! `core/heartbeat.py` (R2, reliability.md §3.1).
//!
//! "Silent death" of a source looks like "everything is fine": the ETW session
//! is lost, auditd did not apply its rules, the eBPF program was unloaded. The
//! mechanism is a heartbeat per source plus a synthetic probe every 60 s.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

/// A detected outage or a failed synthetic probe.
#[derive(Clone, Debug, PartialEq)]
pub struct Incident {
    pub source: String,
    /// "silent" | "stalled" | "probe_failed" | "degraded".
    pub kind: String,
    pub silent_for_s: f64,
    pub detail: String,
}

#[derive(Clone, Debug)]
struct SourceState {
    last_beat_mono: f64,
    last_probe_mono: f64,
    seq: Option<i64>,
    incident_open: bool,
    healthy: bool,
    degraded: bool,
}

/// Public view of a source's liveness.
#[derive(Clone, Debug, PartialEq)]
pub struct SourceHealth {
    pub healthy: bool,
    pub degraded: bool,
    pub silent_for_s: f64,
    pub incident_open: bool,
    pub seq: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeartbeatError {
    InvalidThresholds,
    EmptySource,
    UnregisteredSource,
    NoProbe,
}

impl fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeartbeatError::InvalidThresholds => {
                f.write_str("expected 0 < warn_s < escalate_s <= timeout_s")
            }
            HeartbeatError::EmptySource => f.write_str("source name must be non-empty"),
            HeartbeatError::UnregisteredSource => f.write_str("unregistered source"),
            HeartbeatError::NoProbe => f.write_str("no probe registered"),
        }
    }
}

impl std::error::Error for HeartbeatError {}

type NowFn = Arc<dyn Fn() -> f64 + Send + Sync>;
type ProbeFn = Box<dyn Fn() -> bool + Send + Sync>;
type IncidentFn = Arc<dyn Fn(&Incident) + Send + Sync>;

/// Tracks liveness of telemetry sources.
pub struct HeartbeatMonitor {
    timeout_s: f64,
    warn_s: f64,
    escalate_s: f64,
    #[allow(dead_code)]
    probe_interval_s: f64,
    now_fn: NowFn,
    on_incident: Option<IncidentFn>,
    sources: BTreeMap<String, SourceState>,
    probes: HashMap<String, ProbeFn>,
    incidents: Vec<Incident>,
    warnings: Vec<Incident>,
}

fn monotonic_now_fn() -> NowFn {
    let origin = Instant::now();
    Arc::new(move || origin.elapsed().as_secs_f64())
}

impl HeartbeatMonitor {
    /// Default 60 s timeout; warn at 30 s, incident at 45 s (R2 keeps 25 % margin).
    pub fn new(timeout_s: f64) -> Self {
        Self::with_clock(timeout_s, monotonic_now_fn())
    }

    pub fn with_clock(timeout_s: f64, now_fn: NowFn) -> Self {
        Self::with_thresholds(timeout_s, None, None, now_fn)
            .expect("default heartbeat thresholds are valid for timeout_s > 0")
    }

    /// Explicit thresholds (tests accelerate time).
    pub fn with_thresholds(
        timeout_s: f64,
        warn_s: Option<f64>,
        escalate_s: Option<f64>,
        now_fn: NowFn,
    ) -> Result<Self, HeartbeatError> {
        let warn = warn_s.unwrap_or(timeout_s * 0.5);
        let escalate = escalate_s.unwrap_or(timeout_s * 0.75);
        if !(warn > 0.0 && warn < escalate && escalate <= timeout_s) {
            return Err(HeartbeatError::InvalidThresholds);
        }
        Ok(Self {
            timeout_s,
            warn_s: warn,
            escalate_s: escalate,
            probe_interval_s: 60.0,
            now_fn,
            on_incident: None,
            sources: BTreeMap::new(),
            probes: HashMap::new(),
            incidents: Vec::new(),
            warnings: Vec::new(),
        })
    }

    pub fn with_on_incident(mut self, callback: IncidentFn) -> Self {
        self.on_incident = Some(callback);
        self
    }

    pub fn with_probe_interval(mut self, seconds: f64) -> Self {
        self.probe_interval_s = seconds;
        self
    }

    /// Register a source without a probe.
    pub fn register(&mut self, source: &str) -> Result<(), HeartbeatError> {
        self.register_with_probe(source, None)
    }

    /// Register a source with a synthetic probe.
    pub fn register_with_probe(
        &mut self,
        source: &str,
        probe: Option<ProbeFn>,
    ) -> Result<(), HeartbeatError> {
        if source.is_empty() {
            return Err(HeartbeatError::EmptySource);
        }
        let now = (self.now_fn)();
        self.sources.insert(
            source.to_owned(),
            SourceState {
                last_beat_mono: now,
                last_probe_mono: now,
                seq: None,
                incident_open: false,
                healthy: true,
                degraded: false,
            },
        );
        if let Some(probe) = probe {
            self.probes.insert(source.to_owned(), probe);
        }
        Ok(())
    }

    pub fn sources(&self) -> Vec<String> {
        self.sources.keys().cloned().collect()
    }

    /// Record a heartbeat. Unknown sources are rejected loudly.
    pub fn beat(&mut self, source: &str, seq: Option<i64>) -> Result<(), HeartbeatError> {
        let state = self
            .sources
            .get_mut(source)
            .ok_or(HeartbeatError::UnregisteredSource)?;
        if let (Some(new_seq), Some(old_seq)) = (seq, state.seq) {
            if new_seq < old_seq {
                // Out-of-order heartbeats do not extend liveness.
                return Ok(());
            }
        }
        state.last_beat_mono = (self.now_fn)();
        state.seq = seq.or(state.seq);
        state.healthy = true;
        state.degraded = false;
        state.incident_open = false;
        Ok(())
    }

    /// Run the synthetic probe for a source. A failed probe is an incident.
    #[allow(clippy::redundant_closure)]
    pub fn probe(&mut self, source: &str) -> Result<bool, HeartbeatError> {
        let probe = self.probes.get(source).ok_or(HeartbeatError::NoProbe)?;
        let ok =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| probe())).unwrap_or(false);
        let now = (self.now_fn)();
        let state = self
            .sources
            .get_mut(source)
            .ok_or(HeartbeatError::UnregisteredSource)?;
        state.last_probe_mono = now;
        if !ok {
            let silent = now - state.last_beat_mono;
            self.raise_incident(
                source,
                "probe_failed",
                silent,
                "synthetic probe returned false",
            );
        }
        Ok(ok)
    }

    /// Detect silent sources. Returns incidents opened by this call.
    pub fn check(&mut self) -> Vec<Incident> {
        let now = (self.now_fn)();
        let sources: Vec<String> = self.sources.keys().cloned().collect();
        let mut opened = Vec::new();
        for source in sources {
            let (silence, incident_open, degraded) = {
                let state = &self.sources[&source];
                (
                    now - state.last_beat_mono,
                    state.incident_open,
                    state.degraded,
                )
            };
            if incident_open {
                continue;
            }
            if silence > self.escalate_s {
                let kind = if silence > self.timeout_s {
                    "silent"
                } else {
                    "stalled"
                };
                let inc = self.raise_incident(
                    &source,
                    kind,
                    silence,
                    &format!("no heartbeat for {silence:.1}s"),
                );
                opened.push(inc);
            } else if silence > self.warn_s && !degraded {
                if let Some(state) = self.sources.get_mut(&source) {
                    state.degraded = true;
                }
                let warning = Incident {
                    source: source.clone(),
                    kind: "degraded".to_owned(),
                    silent_for_s: round3(silence),
                    detail: format!("no heartbeat for {silence:.1}s"),
                };
                self.warnings.push(warning.clone());
            }
        }
        opened
    }

    fn raise_incident(
        &mut self,
        source: &str,
        kind: &str,
        silent_for_s: f64,
        detail: &str,
    ) -> Incident {
        if let Some(state) = self.sources.get_mut(source) {
            state.healthy = false;
            if state.incident_open && kind == "silent" {
                return Incident {
                    source: source.to_owned(),
                    kind: kind.to_owned(),
                    silent_for_s: round3(silent_for_s),
                    detail: detail.to_owned(),
                };
            }
            state.incident_open = true;
        }
        let inc = Incident {
            source: source.to_owned(),
            kind: kind.to_owned(),
            silent_for_s: round3(silent_for_s),
            detail: detail.to_owned(),
        };
        self.incidents.push(inc.clone());
        if let Some(callback) = &self.on_incident {
            callback(&inc);
        }
        inc
    }

    pub fn health(&self) -> BTreeMap<String, SourceHealth> {
        let now = (self.now_fn)();
        self.sources
            .iter()
            .map(|(source, state)| {
                (
                    source.clone(),
                    SourceHealth {
                        healthy: state.healthy,
                        degraded: state.degraded,
                        silent_for_s: round3(now - state.last_beat_mono),
                        incident_open: state.incident_open,
                        seq: state.seq,
                    },
                )
            })
            .collect()
    }

    pub fn all_healthy(&self) -> bool {
        self.sources.values().all(|state| state.healthy)
    }

    pub fn incidents(&self) -> &[Incident] {
        &self.incidents
    }

    pub fn warnings(&self) -> &[Incident] {
        &self.warnings
    }
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}
