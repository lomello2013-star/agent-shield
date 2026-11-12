//! Lightweight Rust benchmarks for the reflex path (rules, ingest, gate).
//! Run: cargo run --release --bin bench

use std::path::PathBuf;
use std::time::Instant;

use aidf_core::gate::{AlertBudget, PolicyGate};
use aidf_core::ingest::{IngestConfig, IngestPipeline, P0_PROCESS, P1_FILE};
use aidf_core::rules::{load_rules, RuleEngine};
use aidf_core::types::{Detector, Severity, Verdict};
use serde_json::{json, Value};

fn event() -> Value {
    json!({
        "platform": "windows",
        "source": "win.etw.ti",
        "layer": "kernel",
        "category": "process.start",
        "action": "start",
        "actor": {"pid": 4242, "ppid": 1, "name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe"},
        "object": {"type": "file", "path": "C:\\Users\\public\\doc.txt"},
        "host": {"host_id": "bench", "os": "windows", "version": "10.0", "arch": "x64"},
        "platform_data": {}
    })
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let rules = load_rules(&[root.join("rules").join("base.json").to_str().unwrap()]).unwrap();
    let mut engine = RuleEngine::new(rules).unwrap();
    let event = event();

    let started = Instant::now();
    for _ in 0..10_000 {
        let _ = engine.evaluate(&event);
    }
    let rules_elapsed = started.elapsed().as_secs_f64();

    let pipe = IngestPipeline::new(IngestConfig {
        capacity: 200_000,
        spill_path: None,
        ..IngestConfig::default()
    });
    let started = Instant::now();
    for index in 0..100_000 {
        let priority = if index % 10 == 0 { P0_PROCESS } else { P1_FILE };
        pipe.submit("process.start", &index.to_string(), json!({}), priority)
            .unwrap();
    }
    let ingest_submit_s = started.elapsed().as_secs_f64();
    let drained = pipe.drain(0).len();
    let ingest_total_s = started.elapsed().as_secs_f64();
    let ledger_ok = pipe.ledger_ok();

    let mut gate = PolicyGate::new().with_budget(AlertBudget::new(1, 14.0 * 24.0 * 3600.0));
    let verdict = Verdict::new(
        Detector::Rule,
        "windows",
        1.0,
        Severity::High,
        Some("BENCH-RULE"),
        None,
        "bench",
        "bench",
    );
    let started = Instant::now();
    let mut alerts = 0usize;
    for _ in 0..100_000 {
        if gate.decide(&verdict, "bench-host", "pid:1").alert {
            alerts += 1;
        }
    }
    let gate_s = started.elapsed().as_secs_f64();

    let report = json!({
        "rules": {"events": 10_000, "seconds": rules_elapsed, "events_per_s": round(10_000.0 / rules_elapsed)},
        "ingest": {"events": 100_000, "submit_s": ingest_submit_s, "total_s": ingest_total_s, "drained": drained, "ledger_ok": ledger_ok},
        "gate": {"events": 100_000, "seconds": gate_s, "events_per_s": round(100_000.0 / gate_s), "alerts": alerts},
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" }
    });
    let out = root.join("artifacts").join("rust_bench.json");
    std::fs::write(&out, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

fn round(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}
