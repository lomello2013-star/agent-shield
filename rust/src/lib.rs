//! Rust port of the first AIDefender modules (F19).
//!
//! Scope of this slice: `core/policy.py`, `core/clock.py`, `core/counters.py`.
//! The Python implementation remains the behavioural reference; parity tests live
//! in `tests/` and compare the Rust contract against the Python artifacts.

pub mod clock;
pub mod confirm;
pub mod counters;
pub mod gate;
pub mod heartbeat;
pub mod ingest;
pub mod ipc;
pub mod ml;
pub mod modelpack;
pub mod policy;
pub mod response;
pub mod rules;
pub mod selfprotect;
pub mod types;

pub(crate) mod sha256;
