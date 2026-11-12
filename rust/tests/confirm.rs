use std::sync::{Arc, Mutex};

use aidf_core::confirm::{ConfirmationError, ConfirmationManager};

struct FakeClock {
    now: Arc<Mutex<f64>>,
}

impl FakeClock {
    fn new() -> (Self, Arc<Mutex<f64>>) {
        let now = Arc::new(Mutex::new(100.0));
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

#[test]
fn timeout_rejects_per_immutable_policy() {
    let (fake, now) = FakeClock::new();
    let mut manager = ConfirmationManager::with_clock(30.0, true, fake.now_fn());
    let conf = manager
        .request("act-1", "protected_dir", false, None)
        .unwrap();
    assert_eq!(conf.decision, "pending");
    *now.lock().unwrap() += 31.0;
    let expired = manager.expire();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].decision, "reject");
    assert!(!manager.executable(&conf.confirmation_id));
}

#[test]
fn below_timeout_stays_pending() {
    let (fake, now) = FakeClock::new();
    let mut manager = ConfirmationManager::with_clock(30.0, true, fake.now_fn());
    let conf = manager.request("act-2", "normal", false, None).unwrap();
    *now.lock().unwrap() += 10.0;
    assert!(manager.expire().is_empty());
    assert_eq!(
        manager.get(&conf.confirmation_id).unwrap().decision,
        "pending"
    );
}

#[test]
fn destructive_without_operator_is_queued_never_executed() {
    let mut manager = ConfirmationManager::new(30.0, false);
    let conf = manager.request("terminate", "normal", true, None).unwrap();
    assert!(conf.queued);
    manager
        .resolve(&conf.confirmation_id, "approved", "operator")
        .unwrap();
    assert_eq!(
        manager.get(&conf.confirmation_id).unwrap().decision,
        "pending"
    );
    assert!(!manager.executable(&conf.confirmation_id));
    assert_eq!(manager.pending().len(), 1);
}

#[test]
fn destructive_with_operator_can_be_approved() {
    let mut manager = ConfirmationManager::new(30.0, true);
    let conf = manager.request("terminate", "normal", true, None).unwrap();
    manager
        .resolve(&conf.confirmation_id, "approved", "operator")
        .unwrap();
    assert_eq!(
        manager.get(&conf.confirmation_id).unwrap().decision,
        "approved"
    );
    assert!(manager.executable(&conf.confirmation_id));
}

#[test]
fn reversible_action_approval_and_execution_gate() {
    let mut manager = ConfirmationManager::new(30.0, true);
    let conf = manager.request("suspend", "normal", false, None).unwrap();
    assert!(!manager.executable(&conf.confirmation_id));
    manager
        .resolve(&conf.confirmation_id, "approved", "operator")
        .unwrap();
    assert!(manager.executable(&conf.confirmation_id));
}

#[test]
fn double_resolution_is_idempotent() {
    let mut manager = ConfirmationManager::new(30.0, true);
    let conf = manager
        .request("block_network", "normal", false, None)
        .unwrap();
    manager
        .resolve(&conf.confirmation_id, "rejected", "operator")
        .unwrap();
    manager
        .resolve(&conf.confirmation_id, "approved", "operator")
        .unwrap();
    assert_eq!(
        manager.get(&conf.confirmation_id).unwrap().decision,
        "rejected"
    );
}

#[test]
fn bad_decision_and_level_rejected() {
    let mut manager = ConfirmationManager::new(30.0, true);
    assert!(matches!(
        manager.request("x", "urgent", false, None),
        Err(ConfirmationError::BadLevel(_))
    ));
    let conf = manager.request("x", "normal", false, None).unwrap();
    assert!(matches!(
        manager.resolve(&conf.confirmation_id, "maybe", "operator"),
        Err(ConfirmationError::BadDecision(_))
    ));
}

#[test]
fn unknown_confirmation_raises() {
    let manager = ConfirmationManager::new(30.0, true);
    assert!(matches!(
        manager.try_executable("missing"),
        Err(ConfirmationError::Unknown(_))
    ));
}
