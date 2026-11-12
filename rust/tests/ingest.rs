use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aidf_core::ingest::{
    drain_all, IngestConfig, IngestPipeline, IngestRecord, P0_PROCESS, P1_FILE, P2_NOISE,
};
use serde_json::json;

fn temp_path(name: &str) -> PathBuf {
    // Keep test spills inside the crate target dir: Windows temp may be blocked
    // by the host sandbox, and this keeps the test hermetic.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-tmp");
    let _ = std::fs::create_dir_all(&root);
    root.join(format!("aidf-ingest-{}-{name}", uuid::Uuid::new_v4()))
}

fn pipeline(capacity: usize) -> IngestPipeline {
    IngestPipeline::new(IngestConfig {
        capacity,
        ..IngestConfig::default()
    })
}

fn categories(records: &[IngestRecord]) -> Vec<&str> {
    records
        .iter()
        .map(|record| record.category.as_str())
        .collect()
}

#[test]
fn priority_order_process_before_files() {
    let pipe = pipeline(100);
    pipe.submit("file.write", "f1", json!({}), P1_FILE).unwrap();
    pipe.submit("process.start", "p1", json!({}), P0_PROCESS)
        .unwrap();
    pipe.submit("file.write", "f2", json!({}), P1_FILE).unwrap();
    let got = pipe.drain(10);
    assert_eq!(
        categories(&got),
        vec!["process.start", "file.write", "file.write"]
    );
}

#[test]
fn noise_is_aggregated_not_queued_per_event() {
    let pipe = IngestPipeline::new(IngestConfig {
        capacity: 100,
        aggregation_window_s: 60.0,
        ..IngestConfig::default()
    });
    for _ in 0..50 {
        assert!(pipe
            .submit("auth.failure", "same-key", json!({}), P2_NOISE)
            .unwrap());
    }
    let stats = pipe.stats();
    assert_eq!(stats["queues"]["noise"].as_u64(), Some(0));
    assert_eq!(stats["aggregated"].as_i64(), Some(49));
    pipe.flush_aggregation(true);
    let got = pipe.drain(10);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].count, 50);
    assert_eq!(pipe.stats()["delivered"].as_i64(), Some(50));
    assert!(pipe.ledger_ok());
}

#[test]
fn aggregation_window_expiry_flushes_bucket() {
    let now = Arc::new(Mutex::new(0.0));
    let clock = Arc::clone(&now);
    let pipe = IngestPipeline::with_clock(
        IngestConfig {
            capacity: 10,
            aggregation_window_s: 1.0,
            ..IngestConfig::default()
        },
        Arc::new(move || *clock.lock().unwrap()),
    );
    pipe.submit("net.connect", "k", json!({}), P2_NOISE)
        .unwrap();
    *now.lock().unwrap() = 0.5;
    pipe.submit("net.connect", "k", json!({}), P2_NOISE)
        .unwrap();
    assert_eq!(pipe.stats()["queues"]["noise"].as_u64(), Some(0));
    *now.lock().unwrap() = 2.0;
    pipe.submit("net.connect", "k", json!({}), P2_NOISE)
        .unwrap();
    let got = pipe.drain(10);
    assert_eq!(got[0].count, 2);
    assert!(pipe.ledger_ok());
}

#[test]
fn spill_to_disk_and_replay() {
    let spill = temp_path("spool").join("events.jsonl");
    let pipe = IngestPipeline::new(IngestConfig {
        capacity: 4,
        reserved_ratio: 0.0,
        spill_path: Some(spill.clone()),
        ..IngestConfig::default()
    });
    for i in 0..10 {
        pipe.submit("file.create", &format!("k{i}"), json!({}), P1_FILE)
            .unwrap();
    }
    assert!(pipe.spilled() > 0);
    let got = drain_all(&pipe, 100);
    assert_eq!(pipe.lost(), 0);
    assert_eq!(pipe.received(), 10);
    assert_eq!(pipe.delivered(), 10);
    assert!(pipe.ledger_ok());
    assert!(!spill.exists());
    assert_eq!(got.len(), 10);
}

#[test]
fn loss_is_counted_and_incident_raised_when_no_spill() {
    let incidents = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&incidents);
    let pipe = IngestPipeline::new(IngestConfig {
        capacity: 2,
        reserved_ratio: 0.0,
        ..IngestConfig::default()
    })
    .with_on_incident(Arc::new(move |reason| {
        sink.lock().unwrap().push(reason.to_owned());
    }));
    for i in 0..5 {
        pipe.submit("file.write", &format!("k{i}"), json!({}), P1_FILE)
            .unwrap();
    }
    assert_eq!(pipe.lost(), 3);
    assert!(!incidents.lock().unwrap().is_empty());
    assert_eq!(pipe.stats()["lost"].as_i64(), Some(3));
    assert!(pipe.ledger_ok());
}

#[test]
fn p0_reserved_headroom_survives_noise_storm() {
    let pipe = IngestPipeline::new(IngestConfig {
        capacity: 10,
        reserved_ratio: 0.3,
        ..IngestConfig::default()
    });
    for i in 0..20 {
        pipe.submit("file.write", &format!("f{i}"), json!({}), P1_FILE)
            .unwrap();
    }
    assert!(pipe
        .submit("process.start", "critical", json!({}), P0_PROCESS)
        .unwrap());
    let got = pipe.drain(100);
    assert!(got.iter().any(|record| record.category == "process.start"));
    assert!(pipe.ledger_ok());
}

#[test]
fn ledger_invariant_under_mixed_storm() {
    let spill = temp_path("storm.jsonl");
    let pipe = IngestPipeline::new(IngestConfig {
        capacity: 64,
        reserved_ratio: 0.25,
        spill_path: Some(spill),
        aggregation_window_s: 0.0,
        ..IngestConfig::default()
    });
    for i in 0..1500 {
        if i % 10 == 0 {
            pipe.submit("process.start", &format!("p{i}"), json!({}), P0_PROCESS)
                .unwrap();
        } else if i % 3 == 0 {
            pipe.submit("file.write", &format!("f{i}"), json!({}), P1_FILE)
                .unwrap();
        } else {
            pipe.submit("auth.failure", "noise", json!({}), P2_NOISE)
                .unwrap();
        }
    }
    let mut got = drain_all(&pipe, 200);
    pipe.flush_aggregation(true);
    got.extend(drain_all(&pipe, 200));
    assert!(pipe.ledger_ok(), "{:?}", pipe.stats());
    assert_eq!(pipe.lost(), 0);
    assert_eq!(pipe.delivered(), pipe.received());
    assert_eq!(pipe.loss_ratio(), 0.0);
}

#[test]
fn bad_priority_rejected() {
    let pipe = IngestPipeline::new(IngestConfig::default());
    assert!(pipe.submit("x", "", json!({}), 99).is_err());
}

#[test]
fn backlog_gauge_tracks_queue_depth() {
    let pipe = pipeline(100);
    pipe.submit("process.start", "a", json!({}), P0_PROCESS)
        .unwrap();
    assert_eq!(pipe.stats()["backlog"].as_i64(), Some(1));
    pipe.drain(1);
    assert_eq!(pipe.stats()["backlog"].as_i64(), Some(0));
}
