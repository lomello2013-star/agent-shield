use std::sync::{Arc, Mutex};

use aidf_core::heartbeat::{HeartbeatError, HeartbeatMonitor, Incident};

struct FakeTime {
    now: Arc<Mutex<f64>>,
}

impl FakeTime {
    fn new(start: f64) -> (Self, Arc<Mutex<f64>>) {
        let now = Arc::new(Mutex::new(start));
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

type FakeNow = Arc<Mutex<f64>>;
type IncidentLog = Arc<Mutex<Vec<Incident>>>;

fn make_monitor(timeout_s: f64) -> (HeartbeatMonitor, FakeNow, IncidentLog) {
    let (fake, now) = FakeTime::new(1000.0);
    let incidents = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&incidents);
    let monitor = HeartbeatMonitor::with_clock(timeout_s, fake.now_fn()).with_on_incident(
        Arc::new(move |incident| {
            sink.lock().unwrap().push(incident.clone());
        }),
    );
    (monitor, now, incidents)
}

#[test]
fn beat_keeps_source_healthy() {
    let (mut monitor, now, incidents) = make_monitor(60.0);
    monitor.register("win.etw.ti").unwrap();
    *now.lock().unwrap() += 10.0;
    monitor.beat("win.etw.ti", Some(1)).unwrap();
    assert!(monitor.check().is_empty());
    assert!(incidents.lock().unwrap().is_empty());
    assert!(monitor.health()["win.etw.ti"].healthy);
}

#[test]
fn degraded_warning_then_escalation_keeps_r2_margin() {
    let (mut monitor, now, incidents) = make_monitor(60.0);
    monitor.register("linux.ebpf").unwrap();
    *now.lock().unwrap() += 30.1;
    assert!(monitor.check().is_empty());
    assert_eq!(
        monitor
            .warnings()
            .iter()
            .map(|w| w.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["degraded"]
    );
    assert!(monitor.health()["linux.ebpf"].degraded);

    *now.lock().unwrap() += 15.0;
    let opened = monitor.check();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].kind, "stalled");
    assert!(opened[0].silent_for_s >= 45.0 && opened[0].silent_for_s < 60.0);

    *now.lock().unwrap() += 20.0;
    assert!(monitor.check().is_empty());
    assert_eq!(incidents.lock().unwrap().len(), 1);
}

#[test]
fn heartbeat_clears_degraded_state() {
    let (mut monitor, now, _) = make_monitor(60.0);
    monitor.register("win.etw.ti").unwrap();
    *now.lock().unwrap() += 31.0;
    monitor.check();
    assert!(monitor.health()["win.etw.ti"].degraded);
    monitor.beat("win.etw.ti", Some(2)).unwrap();
    assert!(!monitor.health()["win.etw.ti"].degraded);
    assert!(monitor.health()["win.etw.ti"].healthy);
}

#[test]
fn silent_kind_after_hard_timeout() {
    let (fake, now) = FakeTime::new(1000.0);
    let mut monitor =
        HeartbeatMonitor::with_thresholds(60.0, None, Some(60.0), fake.now_fn()).unwrap();
    monitor.register("linux.ebpf").unwrap();
    *now.lock().unwrap() += 60.1;
    let opened = monitor.check();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].kind, "silent");
}

#[test]
fn beat_clears_incident_and_allows_redetection() {
    let (mut monitor, now, incidents) = make_monitor(10.0);
    monitor.register("auditd").unwrap();
    *now.lock().unwrap() += 20.0;
    monitor.check();
    monitor.beat("auditd", None).unwrap();
    assert!(!monitor.health()["auditd"].incident_open);
    *now.lock().unwrap() += 20.0;
    assert_eq!(monitor.check().len(), 1);
    assert_eq!(incidents.lock().unwrap().len(), 2);
}

#[test]
fn out_of_order_heartbeat_does_not_extend_liveness() {
    let (mut monitor, now, _) = make_monitor(10.0);
    monitor.register("src").unwrap();
    monitor.beat("src", Some(5)).unwrap();
    *now.lock().unwrap() += 10.0;
    monitor.beat("src", Some(4)).unwrap();
    *now.lock().unwrap() += 1.0;
    assert_eq!(monitor.check().len(), 1);
}

#[test]
fn probe_failure_raises_incident() {
    let (mut monitor, _, incidents) = make_monitor(60.0);
    monitor
        .register_with_probe("etw", Some(Box::new(|| false)))
        .unwrap();
    assert!(!monitor.probe("etw").unwrap());
    assert_eq!(incidents.lock().unwrap()[0].kind, "probe_failed");
}

#[test]
fn probe_exception_counts_as_failure() {
    let (mut monitor, _, incidents) = make_monitor(60.0);
    monitor
        .register_with_probe("fanotify", Some(Box::new(|| panic!("provider gone"))))
        .unwrap();
    assert!(!monitor.probe("fanotify").unwrap());
    assert_eq!(incidents.lock().unwrap()[0].kind, "probe_failed");
}

#[test]
fn probe_success_and_missing_probe() {
    let (mut monitor, _, _) = make_monitor(60.0);
    monitor
        .register_with_probe("wfp", Some(Box::new(|| true)))
        .unwrap();
    assert!(monitor.probe("wfp").unwrap());
    monitor.register("other").unwrap();
    assert_eq!(monitor.probe("other"), Err(HeartbeatError::NoProbe));
}

#[test]
fn unknown_source_rejected() {
    let (mut monitor, _, _) = make_monitor(60.0);
    assert_eq!(
        monitor.beat("ghost", None),
        Err(HeartbeatError::UnregisteredSource)
    );
    assert_eq!(monitor.register(""), Err(HeartbeatError::EmptySource));
}

#[test]
fn all_healthy_reflects_state() {
    let (mut monitor, now, _) = make_monitor(5.0);
    monitor.register("a").unwrap();
    monitor.register("b").unwrap();
    assert!(monitor.all_healthy());
    *now.lock().unwrap() += 10.0;
    monitor.check();
    assert!(!monitor.all_healthy());
}
