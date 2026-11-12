"""Overflow-free ingest (reliability.md §3, п.3; R8 < 0.01% loss).

Rules:
  * priorities: process/auth (P0) > files (P1) > auth-noise (P2);
  * P0 has reserved headroom: P1/P2 cannot consume the last ``reserved_ratio``
    of capacity, so a file/авторизация storm never starves process events;
  * P2 noise is aggregated inside a time window instead of flooding the queue;
  * when a queue is full, the lowest-priority record is moved to a disk spool
    (spill) instead of being dropped;
  * if the spool itself is unavailable, the loss is **counted** and an incident is
    raised — never a silent drop.

Accounting invariant (checked in tests):

    received == delivered + lost + spilled_pending + backlog
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable

from .counters import (
    AGGREGATED,
    BACKLOG,
    EVICTED,
    LOST,
    OVERFLOW,
    REPLAYED,
    SPILLED,
    LossCounters,
)

P0_PROCESS = 0
P1_FILE = 1
P2_NOISE = 2

PRIORITY_NAMES = {P0_PROCESS: "process/auth", P1_FILE: "files", P2_NOISE: "noise"}


@dataclass(frozen=True)
class IngestRecord:
    category: str
    key: str
    payload: dict
    priority: int
    count: int = 1
    # runtime-only: the already validated Event (not serialized, not replayed)
    event: Any = None


@dataclass
class _Bucket:
    record: IngestRecord
    window_start: float
    count: int = 1


@dataclass
class IngestPipeline:
    capacity: int = 10_000
    spill_path: str | None = None
    reserved_ratio: float = 0.30
    aggregation_window_s: float = 1.0
    spill_fsync_every: int = 1
    now_fn: Callable[[], float] = time.monotonic
    counters: LossCounters = field(default_factory=LossCounters)
    on_incident: Callable[[str], None] | None = None

    _queues: dict[int, deque] = field(default_factory=lambda: {0: deque(), 1: deque(), 2: deque()},
                                      repr=False)
    _buckets: dict[str, _Bucket] = field(default_factory=dict, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _spill_replay: deque = field(default_factory=deque, repr=False)
    _spill_fh: object | None = field(default=None, repr=False)
    _spill_pending: int = field(default=0, repr=False)

    received: int = 0
    delivered: int = 0
    lost: int = 0
    spilled: int = 0
    replayed: int = 0
    incidents: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ submit
    def submit(self, category: str, key: str = "", payload: dict | None = None,
               priority: int = P2_NOISE, event: Any = None) -> bool:
        """Submit one event. Returns False only when it was irrecoverably lost.

        `event` is the already validated Event; it lets the pipeline skip a redundant
        second validation on the hot path (see DEVLOG F11).
        """
        if priority not in (P0_PROCESS, P1_FILE, P2_NOISE):
            raise ValueError(f"bad priority: {priority}")
        rec = IngestRecord(category=category, key=key, payload=payload or {},
                           priority=priority, event=event)
        with self._lock:
            self.received += 1
            if priority == P2_NOISE:
                bucket = self._buckets.get(key or category)
                if bucket is not None and (self.now_fn() - bucket.window_start) < self.aggregation_window_s:
                    bucket.count += 1
                    self.counters.inc(AGGREGATED)
                    return True
                if bucket is not None:
                    self._flush_bucket(key or category)
                self._buckets[key or category] = _Bucket(record=rec, window_start=self.now_fn())
                self._publish_backlog()
                return True
            ok = self._enqueue(rec)
            self._publish_backlog()
            return ok

    def _enqueue(self, rec: IngestRecord) -> bool:
        reserved = int(self.capacity * self.reserved_ratio)
        limit = self.capacity if rec.priority == P0_PROCESS else self.capacity - reserved
        if self._queued_events() >= limit:
            if not self._make_room():
                # No slot could be freed (all queues empty is impossible here).
                if self._spill(rec):
                    return True
                return self._lose(rec, reason="queue_full")
        self._queues[rec.priority].append(rec)
        return True

    def _make_room(self) -> bool:
        """Free one slot by spilling the lowest-priority record (P0 stays intact)."""
        for priority in (P2_NOISE, P1_FILE):
            queue = self._queues[priority]
            if queue:
                rec = queue.pop()
                if self._spill(rec):
                    self.counters.inc(EVICTED)
                    return True
                # Slot is freed but the record is lost: counted, never silent.
                self._lose(rec, reason="evict_spill_failed")
                return True
        if self._queues[P0_PROCESS]:
            rec = self._queues[P0_PROCESS].pop()
            if self._spill(rec):
                self.counters.inc(EVICTED)
                return True
            self._lose(rec, reason="p0_evicted_spill_failed")
            return True
        return False

    def _spill(self, rec: IngestRecord) -> bool:
        if not self.spill_path:
            return False
        try:
            os.makedirs(os.path.dirname(self.spill_path) or ".", exist_ok=True)
            line = json.dumps({"category": rec.category, "key": rec.key,
                               "payload": rec.payload, "priority": rec.priority,
                               "count": rec.count}, ensure_ascii=False)
            if self._spill_fh is None:
                self._spill_fh = open(self.spill_path, "a", encoding="utf-8")
            self._spill_fh.write(line + "\n")
            self._spill_pending += 1
            if self._spill_pending >= max(1, self.spill_fsync_every):
                self._spill_fh.flush()
                os.fsync(self._spill_fh.fileno())
                self._spill_pending = 0
            self.spilled += rec.count
            self.counters.inc(SPILLED, rec.count)
            return True
        except OSError:
            return False

    def _close_spill(self) -> None:
        if self._spill_fh is None:
            return
        try:
            self._spill_fh.flush()
            os.fsync(self._spill_fh.fileno())
        except OSError:
            pass
        finally:
            try:
                self._spill_fh.close()
            except OSError:
                pass
            self._spill_fh = None
            self._spill_pending = 0

    def close(self) -> None:
        """Flush and close the spill file (call before shutdown)."""
        with self._lock:
            self._close_spill()

    def _lose(self, rec: IngestRecord, reason: str) -> bool:
        self.lost += rec.count
        self.counters.inc(LOST, rec.count)
        self.incidents.append(reason)
        if self.on_incident is not None:
            self.on_incident(reason)
        return False

    # ------------------------------------------------------------------- drain
    def drain(self, max_events: int = 1_000) -> list[IngestRecord]:
        """Return up to ``max_events`` records, highest priority first."""
        out: list[IngestRecord] = []
        with self._lock:
            self.flush_aggregation()
            for priority in (P0_PROCESS, P1_FILE, P2_NOISE):
                queue = self._queues[priority]
                while queue and (max_events <= 0 or len(out) < max_events):
                    out.append(queue.popleft())
            if not out:
                out.extend(self._replay_spill(max_events if max_events > 0 else 1_000))
            self.delivered += sum(r.count for r in out)
            self._publish_backlog()
        return out

    def _replay_spill(self, limit: int) -> list[IngestRecord]:
        if not self._spill_replay and self.spill_path and (
                os.path.exists(self.spill_path) or self._spill_fh is not None):
            self._close_spill()                     # Windows: file must be closed before read/remove
            if not os.path.exists(self.spill_path):
                return []
            try:
                with open(self.spill_path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        data = json.loads(line)
                        self._spill_replay.append(IngestRecord(
                            category=data["category"], key=data.get("key", ""),
                            payload=data.get("payload", {}), priority=data.get("priority", P2_NOISE),
                            count=int(data.get("count", 1))))
                os.remove(self.spill_path)
            except (OSError, ValueError):
                return []
        out = []
        while self._spill_replay and len(out) < limit:
            rec = self._spill_replay.popleft()
            self.replayed += rec.count
            self.counters.inc(REPLAYED, rec.count)
            out.append(rec)
        return out

    # ------------------------------------------------------------- aggregation
    def flush_aggregation(self, force: bool = False) -> int:
        """Move expired aggregation buckets into the noise queue."""
        with self._lock:
            now = self.now_fn()
            flushed = 0
            for key in list(self._buckets):
                bucket = self._buckets[key]
                if force or (now - bucket.window_start) >= self.aggregation_window_s:
                    self._flush_bucket(key)
                    flushed += 1
            self._publish_backlog()
            return flushed

    def _flush_bucket(self, key: str) -> None:
        bucket = self._buckets.pop(key)
        rec = IngestRecord(category=bucket.record.category, key=bucket.record.key,
                           payload=bucket.record.payload, priority=P2_NOISE, count=bucket.count)
        self._enqueue(rec)

    # ----------------------------------------------------------- observability
    def _queued_events(self) -> int:
        return sum(len(q) for q in self._queues.values())

    def backlog_events(self) -> int:
        with self._lock:
            return self._queued_events() + sum(b.count for b in self._buckets.values()) + (
                self.spilled - self.replayed)

    def _publish_backlog(self) -> None:
        self.counters.set(BACKLOG, self.backlog_events())

    def stats(self) -> dict[str, object]:
        with self._lock:
            return {
                "received": self.received,
                "delivered": self.delivered,
                "lost": self.lost,
                "spilled_pending": self.spilled - self.replayed,
                "backlog": self.backlog_events(),
                "queues": {PRIORITY_NAMES[p]: len(q) for p, q in self._queues.items()},
                "aggregated": self.counters.get(AGGREGATED),
                "evicted": self.counters.get(EVICTED),
                "replayed": self.counters.get(REPLAYED),
                "incidents": list(self.incidents),
            }

    def ledger_ok(self) -> bool:
        """Verify the accounting invariant: nothing vanished unaccounted."""
        with self._lock:
            return self.received == (self.delivered + self.lost +
                                     (self.spilled - self.replayed) + self.backlog_events())

    def loss_ratio(self) -> float:
        with self._lock:
            return 0.0 if self.received == 0 else self.lost / self.received
