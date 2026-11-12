use std::cell::Cell;

use aidf_core::clock::{MonotonicClock, TimeSource};

struct FakeTime {
    mono: Cell<f64>,
    wall: Cell<f64>,
}

impl FakeTime {
    fn new(mono: f64, wall: f64) -> Self {
        Self {
            mono: Cell::new(mono),
            wall: Cell::new(wall),
        }
    }
}

impl TimeSource for FakeTime {
    fn mono(&self) -> f64 {
        self.mono.get()
    }

    fn wall(&self) -> f64 {
        self.wall.get()
    }
}

#[test]
fn no_jump_when_clocks_agree() {
    let fake = FakeTime::new(1000.0, 1_700_000_000.0);
    let mut clock = MonotonicClock::new(&fake, 5.0);
    fake.mono.set(1010.0);
    fake.wall.set(1_700_000_010.0);
    assert!(clock.detect_jump().is_none());
    assert!(clock.jumps().is_empty());
}

#[test]
fn forward_wall_jump_detected() {
    let fake = FakeTime::new(1000.0, 1_700_000_000.0);
    let mut clock = MonotonicClock::new(&fake, 5.0);
    fake.mono.set(1001.0);
    fake.wall.set(1_700_000_060.0);
    let jump = clock.detect_jump().expect("jump must be detected");
    assert_eq!(jump.skew_s.round() as i64, 59);
    assert_eq!(clock.jumps().len(), 1);
}

#[test]
fn backward_wall_jump_detected() {
    let fake = FakeTime::new(1000.0, 1_700_000_000.0);
    let mut clock = MonotonicClock::new(&fake, 5.0);
    fake.mono.set(1002.0);
    fake.wall.set(1_699_999_970.0);
    let jump = clock.detect_jump().expect("jump must be detected");
    assert!(jump.skew_s < 0.0);
}

#[test]
fn monotonic_ns_is_integer_and_advances() {
    let fake = FakeTime::new(1000.0, 1_700_000_000.0);
    let clock = MonotonicClock::new(&fake, 5.0);
    let first = clock.mono_ns();
    fake.mono.set(1001.0);
    let second = clock.mono_ns();
    assert_eq!(second - first, 1_000_000_000);
}
