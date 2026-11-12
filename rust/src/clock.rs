//! Monotonic clock and wall-clock jump detection — Rust port of `core/clock.py`.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Time source abstraction; production uses [`SystemTimeSource`], tests use a
/// fake source with controllable values.
pub trait TimeSource {
    fn mono(&self) -> f64;
    fn wall(&self) -> f64;
}

/// Production time source: monotonic time since construction, wall-clock time
/// as Unix epoch seconds.
pub struct SystemTimeSource {
    origin: Instant,
}

impl SystemTimeSource {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemTimeSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for SystemTimeSource {
    fn mono(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }

    fn wall(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64())
            .unwrap_or(0.0)
    }
}

impl<T: TimeSource + ?Sized> TimeSource for &T {
    fn mono(&self) -> f64 {
        (**self).mono()
    }

    fn wall(&self) -> f64 {
        (**self).wall()
    }
}

/// Detected discontinuity between wall clock and monotonic clock.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ClockJump {
    pub wall_delta_s: f64,
    pub mono_delta_s: f64,
    pub skew_s: f64,
}

/// Clock that never goes backwards and detects wall-clock jumps.
pub struct MonotonicClock<S: TimeSource> {
    source: S,
    jump_threshold_s: f64,
    last_mono: f64,
    last_wall: f64,
    jumps: Vec<ClockJump>,
}

impl<S: TimeSource> MonotonicClock<S> {
    pub fn new(source: S, jump_threshold_s: f64) -> Self {
        let last_mono = source.mono();
        let last_wall = source.wall();
        Self {
            source,
            jump_threshold_s,
            last_mono,
            last_wall,
            jumps: Vec::new(),
        }
    }

    pub fn mono(&self) -> f64 {
        self.source.mono()
    }

    pub fn mono_ns(&self) -> i64 {
        (self.mono() * 1_000_000_000.0) as i64
    }

    pub fn wall(&self) -> f64 {
        self.source.wall()
    }

    pub fn jumps(&self) -> &[ClockJump] {
        &self.jumps
    }

    /// Compare wall vs monotonic delta; record and return a jump if any.
    pub fn detect_jump(&mut self) -> Option<ClockJump> {
        let mono_now = self.mono();
        let wall_now = self.wall();
        let mono_delta = mono_now - self.last_mono;
        let wall_delta = wall_now - self.last_wall;
        let skew = wall_delta - mono_delta;
        self.last_mono = mono_now;
        self.last_wall = wall_now;

        if skew.abs() >= self.jump_threshold_s {
            let jump = ClockJump {
                wall_delta_s: wall_delta,
                mono_delta_s: mono_delta,
                skew_s: skew,
            };
            self.jumps.push(jump);
            Some(jump)
        } else {
            None
        }
    }
}

impl MonotonicClock<SystemTimeSource> {
    /// Clock with the default 5-second jump threshold.
    pub fn system() -> Self {
        Self::new(SystemTimeSource::new(), 5.0)
    }
}
