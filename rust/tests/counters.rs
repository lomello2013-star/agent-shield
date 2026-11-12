use std::sync::{Arc, Mutex};
use std::thread;

use aidf_core::counters::{LossCounters, BACKLOG, LOST, OVERFLOW};

#[test]
fn counters_increment_and_snapshot() {
    let counters = LossCounters::new();
    counters.inc_one(LOST).unwrap();
    counters.inc(LOST, 2).unwrap();
    counters.inc(BACKLOG, 5).unwrap();
    assert_eq!(counters.get(LOST), 3);
    assert_eq!(counters.snapshot()[BACKLOG], 5);
}

#[test]
fn loss_callback_fires_for_lost_and_overflow_only() {
    let seen = Arc::new(Mutex::new(Vec::<(String, i64)>::new()));
    let sink = Arc::clone(&seen);
    let counters = LossCounters::with_on_loss(move |name, n| {
        sink.lock().unwrap().push((name.to_string(), n));
    });
    counters.inc(BACKLOG, 10).unwrap();
    counters.inc(LOST, 2).unwrap();
    counters.inc(OVERFLOW, 1).unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(LOST.to_string(), 2), (OVERFLOW.to_string(), 1)]
    );
}

#[test]
fn negative_delta_rejected() {
    let counters = LossCounters::new();
    assert!(counters.inc(LOST, -1).is_err());
    assert_eq!(counters.get(LOST), 0);
}

#[test]
fn clean_state() {
    let counters = LossCounters::new();
    assert!(counters.is_clean());
    counters.inc_one(OVERFLOW).unwrap();
    assert!(!counters.is_clean());
    assert_eq!(counters.loss_total(), 1);
}

#[test]
fn set_updates_gauge() {
    let counters = LossCounters::new();
    counters.set(BACKLOG, 42);
    assert_eq!(counters.get(BACKLOG), 42);
}

#[test]
fn concurrent_increments_are_not_lost() {
    let counters = Arc::new(LossCounters::new());
    let mut workers = Vec::new();
    for _ in 0..4 {
        let counters = Arc::clone(&counters);
        workers.push(thread::spawn(move || {
            for _ in 0..1000 {
                counters.inc_one(LOST).unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(counters.get(LOST), 4000);
    assert_eq!(counters.loss_total(), 4000);
}
