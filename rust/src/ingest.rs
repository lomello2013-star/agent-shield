//! Overflow-free ingest — Rust port of `core/ingest.py` (R8).
//!
//! Priorities: P0 process/auth > P1 files > P2 noise. P1/P2 cannot consume the
//! reserved tail of capacity; P2 is aggregated in a time window; when a queue is
//! full the lowest-priority record is moved to a disk spool; if the spool is
//! unavailable the loss is counted and an incident is raised, never silent.
//!
//! Accounting invariant:
//! `received == delivered + lost + spilled_pending + backlog`.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::counters::{LossCounters, AGGREGATED, BACKLOG, EVICTED, LOST, REPLAYED, SPILLED};

pub const P0_PROCESS: i32 = 0;
pub const P1_FILE: i32 = 1;
pub const P2_NOISE: i32 = 2;

pub fn priority_name(priority: i32) -> &'static str {
    match priority {
        P0_PROCESS => "process/auth",
        P1_FILE => "files",
        P2_NOISE => "noise",
        _ => "unknown",
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestRecord {
    pub category: String,
    pub key: String,
    pub payload: Value,
    pub priority: i32,
    pub count: i64,
    /// Runtime-only already validated event; never serialized/replayed.
    #[serde(skip)]
    pub event: Option<Value>,
}

impl IngestRecord {
    pub fn new(category: &str, key: &str, payload: Value, priority: i32) -> Self {
        Self {
            category: category.to_owned(),
            key: key.to_owned(),
            payload,
            priority,
            count: 1,
            event: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct SpillRecord<'a> {
    category: &'a str,
    key: &'a str,
    payload: &'a Value,
    priority: i32,
    count: i64,
}

#[derive(Clone, Debug)]
struct Bucket {
    record: IngestRecord,
    window_start: f64,
    count: i64,
}

#[derive(Default)]
struct Inner {
    queues: [VecDeque<IngestRecord>; 3],
    buckets: BTreeMap<String, Bucket>,
    spill_replay: VecDeque<IngestRecord>,
    spill_file: Option<File>,
    spill_pending: usize,
    received: i64,
    delivered: i64,
    lost: i64,
    spilled: i64,
    replayed: i64,
    incidents: Vec<String>,
}

impl Inner {
    fn queued_events(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }

    fn backlog_events(&self) -> i64 {
        let queued = self.queued_events() as i64;
        let buckets: i64 = self.buckets.values().map(|bucket| bucket.count).sum();
        queued + buckets + (self.spilled - self.replayed)
    }
}

#[derive(Clone, Debug)]
pub struct IngestConfig {
    pub capacity: usize,
    pub spill_path: Option<PathBuf>,
    pub reserved_ratio: f64,
    pub aggregation_window_s: f64,
    pub spill_fsync_every: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            spill_path: None,
            reserved_ratio: 0.30,
            aggregation_window_s: 1.0,
            spill_fsync_every: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestError {
    BadPriority,
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestError::BadPriority => f.write_str("bad priority"),
        }
    }
}

impl std::error::Error for IngestError {}

type NowFn = Arc<dyn Fn() -> f64 + Send + Sync>;
type IncidentFn = Arc<dyn Fn(&str) + Send + Sync>;

pub struct IngestPipeline {
    config: IngestConfig,
    now_fn: NowFn,
    on_incident: Option<IncidentFn>,
    counters: LossCounters,
    inner: Mutex<Inner>,
}

impl IngestPipeline {
    pub fn new(config: IngestConfig) -> Self {
        let origin = Instant::now();
        Self::with_clock(config, Arc::new(move || origin.elapsed().as_secs_f64()))
    }

    pub fn with_clock(config: IngestConfig, now_fn: NowFn) -> Self {
        Self {
            config,
            now_fn,
            on_incident: None,
            counters: LossCounters::new(),
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn with_on_incident(mut self, callback: IncidentFn) -> Self {
        self.on_incident = Some(callback);
        self
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // ------------------------------------------------------------------ submit
    pub fn submit(
        &self,
        category: &str,
        key: &str,
        payload: Value,
        priority: i32,
    ) -> Result<bool, IngestError> {
        if !(P0_PROCESS..=P2_NOISE).contains(&priority) {
            return Err(IngestError::BadPriority);
        }
        let mut inner = self.lock();
        inner.received += 1;

        if priority == P2_NOISE {
            let bucket_key = if key.is_empty() { category } else { key };
            let now = (self.now_fn)();
            if let Some(bucket) = inner.buckets.get(bucket_key) {
                if now - bucket.window_start < self.config.aggregation_window_s {
                    if let Some(bucket) = inner.buckets.get_mut(bucket_key) {
                        bucket.count += 1;
                    }
                    self.counters.inc(AGGREGATED, 1).ok();
                    return Ok(true);
                }
                self.flush_bucket(&mut inner, bucket_key);
            }
            inner.buckets.insert(
                bucket_key.to_owned(),
                Bucket {
                    record: IngestRecord::new(category, key, payload, priority),
                    window_start: now,
                    count: 1,
                },
            );
            self.publish_backlog(&mut inner);
            return Ok(true);
        }

        let ok = self.enqueue(
            &mut inner,
            IngestRecord::new(category, key, payload, priority),
        );
        self.publish_backlog(&mut inner);
        Ok(ok)
    }

    fn enqueue(&self, inner: &mut Inner, record: IngestRecord) -> bool {
        let reserved = (self.config.capacity as f64 * self.config.reserved_ratio) as usize;
        let limit = if record.priority == P0_PROCESS {
            self.config.capacity
        } else {
            self.config.capacity.saturating_sub(reserved)
        };
        if inner.queued_events() >= limit && !self.make_room(inner) {
            if self.spill(inner, &record) {
                return true;
            }
            return self.lose(inner, &record, "queue_full");
        }
        inner.queues[record.priority as usize].push_back(record);
        true
    }

    fn make_room(&self, inner: &mut Inner) -> bool {
        for priority in [P2_NOISE, P1_FILE] {
            if let Some(record) = inner.queues[priority as usize].pop_back() {
                if self.spill(inner, &record) {
                    self.counters.inc(EVICTED, 1).ok();
                    return true;
                }
                self.lose(inner, &record, "evict_spill_failed");
                return true;
            }
        }
        if let Some(record) = inner.queues[P0_PROCESS as usize].pop_back() {
            if self.spill(inner, &record) {
                self.counters.inc(EVICTED, 1).ok();
                return true;
            }
            self.lose(inner, &record, "p0_evicted_spill_failed");
            return true;
        }
        false
    }

    fn spill(&self, inner: &mut Inner, record: &IngestRecord) -> bool {
        let Some(path) = &self.config.spill_path else {
            return false;
        };
        let result = (|| -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let body = serde_json::to_string(&SpillRecord {
                category: &record.category,
                key: &record.key,
                payload: &record.payload,
                priority: record.priority,
                count: record.count,
            })
            .map_err(std::io::Error::other)?;
            if inner.spill_file.is_none() {
                inner.spill_file = Some(OpenOptions::new().create(true).append(true).open(path)?);
            }
            let file = inner.spill_file.as_mut().expect("spill file opened");
            file.write_all(body.as_bytes())?;
            file.write_all(b"\n")?;
            inner.spill_pending += 1;
            if inner.spill_pending >= self.config.spill_fsync_every.max(1) {
                file.flush()?;
                file.sync_data()?;
                inner.spill_pending = 0;
            }
            Ok(())
        })();
        if result.is_err() {
            return false;
        }
        inner.spilled += record.count;
        self.counters.inc(SPILLED, record.count).ok();
        true
    }

    fn close_spill(&self, inner: &mut Inner) {
        if let Some(mut file) = inner.spill_file.take() {
            let _ = file.flush();
            let _ = file.sync_data();
        }
        inner.spill_pending = 0;
    }

    fn lose(&self, inner: &mut Inner, record: &IngestRecord, reason: &str) -> bool {
        inner.lost += record.count;
        self.counters.inc(LOST, record.count).ok();
        inner.incidents.push(reason.to_owned());
        if let Some(callback) = &self.on_incident {
            callback(reason);
        }
        false
    }

    // ------------------------------------------------------------------- drain
    pub fn drain(&self, max_events: usize) -> Vec<IngestRecord> {
        let mut inner = self.lock();
        self.flush_aggregation_locked(&mut inner, false);
        let mut out = Vec::new();
        for priority in [P0_PROCESS, P1_FILE, P2_NOISE] {
            let queue = &mut inner.queues[priority as usize];
            while !queue.is_empty() && (max_events == 0 || out.len() < max_events) {
                if let Some(record) = queue.pop_front() {
                    out.push(record);
                }
            }
        }
        if out.is_empty() {
            let limit = if max_events == 0 { 1_000 } else { max_events };
            out = self.replay_spill(&mut inner, limit);
        }
        inner.delivered += out.iter().map(|record| record.count).sum::<i64>();
        self.publish_backlog(&mut inner);
        out
    }

    fn replay_spill(&self, inner: &mut Inner, limit: usize) -> Vec<IngestRecord> {
        if inner.spill_replay.is_empty() {
            let path = self.config.spill_path.as_ref();
            let path_exists = path.is_some_and(|p| p.exists());
            if path.is_none() || (!path_exists && inner.spill_file.is_none()) {
                return Vec::new();
            }
            self.close_spill(inner);
            let Some(path) = path else {
                return Vec::new();
            };
            if !path.exists() {
                return Vec::new();
            }
            let file = match File::open(path) {
                Ok(file) => file,
                Err(_) => return Vec::new(),
            };
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(data) = serde_json::from_str::<Value>(line) else {
                    return Vec::new();
                };
                let Ok(record) = serde_json::from_value::<IngestRecord>(data) else {
                    return Vec::new();
                };
                inner.spill_replay.push_back(record);
            }
            let _ = std::fs::remove_file(path);
        }
        let mut out = Vec::new();
        while let Some(record) = inner.spill_replay.pop_front() {
            inner.replayed += record.count;
            self.counters.inc(REPLAYED, record.count).ok();
            out.push(record);
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    // ------------------------------------------------------------- aggregation
    pub fn flush_aggregation(&self, force: bool) -> usize {
        let mut inner = self.lock();
        let flushed = self.flush_aggregation_locked(&mut inner, force);
        self.publish_backlog(&mut inner);
        flushed
    }

    fn flush_aggregation_locked(&self, inner: &mut Inner, force: bool) -> usize {
        let now = (self.now_fn)();
        let keys: Vec<String> = inner.buckets.keys().cloned().collect();
        let mut flushed = 0;
        for key in keys {
            let expired = inner.buckets.get(&key).is_some_and(|bucket| {
                force || now - bucket.window_start >= self.config.aggregation_window_s
            });
            if expired {
                self.flush_bucket(inner, &key);
                flushed += 1;
            }
        }
        flushed
    }

    fn flush_bucket(&self, inner: &mut Inner, key: &str) {
        if let Some(bucket) = inner.buckets.remove(key) {
            let record = IngestRecord {
                category: bucket.record.category,
                key: bucket.record.key,
                payload: bucket.record.payload,
                priority: P2_NOISE,
                count: bucket.count,
                event: None,
            };
            self.enqueue(inner, record);
        }
    }

    // ----------------------------------------------------------- observability
    pub fn backlog_events(&self) -> i64 {
        self.lock().backlog_events()
    }

    fn publish_backlog(&self, inner: &mut Inner) {
        let backlog = inner.backlog_events();
        self.counters.set(BACKLOG, backlog);
    }

    pub fn stats(&self) -> Value {
        let inner = self.lock();
        let queues: BTreeMap<&str, usize> = [
            ("process/auth", inner.queues[0].len()),
            ("files", inner.queues[1].len()),
            ("noise", inner.queues[2].len()),
        ]
        .into_iter()
        .collect();
        serde_json::json!({
            "received": inner.received,
            "delivered": inner.delivered,
            "lost": inner.lost,
            "spilled_pending": inner.spilled - inner.replayed,
            "backlog": inner.backlog_events(),
            "queues": queues,
            "aggregated": self.counters.get(AGGREGATED),
            "evicted": self.counters.get(EVICTED),
            "replayed": self.counters.get(REPLAYED),
            "incidents": inner.incidents.clone(),
        })
    }

    pub fn ledger_ok(&self) -> bool {
        let inner = self.lock();
        inner.received
            == inner.delivered
                + inner.lost
                + (inner.spilled - inner.replayed)
                + inner.backlog_events()
    }

    pub fn loss_ratio(&self) -> f64 {
        let inner = self.lock();
        if inner.received == 0 {
            0.0
        } else {
            inner.lost as f64 / inner.received as f64
        }
    }

    pub fn close(&self) {
        let mut inner = self.lock();
        self.close_spill(&mut inner);
    }

    pub fn received(&self) -> i64 {
        self.lock().received
    }

    pub fn delivered(&self) -> i64 {
        self.lock().delivered
    }

    pub fn lost(&self) -> i64 {
        self.lock().lost
    }

    pub fn spilled(&self) -> i64 {
        self.lock().spilled
    }

    pub fn replayed(&self) -> i64 {
        self.lock().replayed
    }
}

impl Drop for IngestPipeline {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            self.close_spill(&mut inner);
        }
    }
}

/// Helper mirroring Python's `drain_all` test utility.
pub fn drain_all(pipeline: &IngestPipeline, batch: usize) -> Vec<IngestRecord> {
    let mut out = Vec::new();
    loop {
        pipeline.flush_aggregation(true);
        let chunk = pipeline.drain(batch);
        if chunk.is_empty() {
            break;
        }
        out.extend(chunk);
    }
    out
}

/// Path helper for spill paths (kept public for tests).
pub fn spill_path(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref().to_path_buf()
}
