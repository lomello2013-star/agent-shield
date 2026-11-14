"""Durable SQLite outbox for connector reports.

P0 is never evicted. Retries use exponential backoff. Duplicate `report_id`s
are ignored (idempotency is enforced by the connector, per `stml/v0`).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from stml.contracts.v0 import PRIORITY_ORDER, Priority, Report


@dataclass(frozen=True)
class SpoolItem:
    row_id: int
    report_id: str
    priority: Priority
    payload: str
    attempts: int
    created_at: float

    def report(self) -> Report:
        return Report.model_validate_json(self.payload)


class Spool:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL UNIQUE,
                priority INTEGER NOT NULL,
                payload TEXT NOT NULL,
                created_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at REAL NOT NULL DEFAULT 0,
                acked INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self._db.commit()

    # -- write -----------------------------------------------------------
    def enqueue(self, report: Report) -> bool:
        priority = PRIORITY_ORDER[report.priority]
        now = time.time()
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO outbox(report_id, priority, payload, created_at, next_attempt_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (report.report_id, priority, report.model_dump_json(), now, now),
                )
                self._db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def mark_attempt(self, row_id: int, attempts: int, delay_s: float) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE outbox SET attempts = ?, next_attempt_at = ? WHERE id = ?",
                (attempts, time.time() + delay_s, row_id),
            )
            self._db.commit()

    def ack(self, report_ids: list[str]) -> int:
        if not report_ids:
            return 0
        marks = ",".join("?" for _ in report_ids)
        with self._lock:
            cur = self._db.execute(
                f"UPDATE outbox SET acked = 1 WHERE report_id IN ({marks})", report_ids
            )
            self._db.commit()
            return cur.rowcount

    # -- read ------------------------------------------------------------
    def pending_count(self) -> int:
        with self._lock:
            return int(
                self._db.execute(
                    "SELECT COUNT(*) FROM outbox WHERE acked = 0"
                ).fetchone()[0]
            )

    def p0_count(self) -> int:
        with self._lock:
            return int(
                self._db.execute(
                    "SELECT COUNT(*) FROM outbox WHERE acked = 0 AND priority = 0"
                ).fetchone()[0]
            )

    def peek(self, limit: int = 50, now: float | None = None) -> list[SpoolItem]:
        now = time.time() if now is None else now
        with self._lock:
            rows = self._db.execute(
                "SELECT id, report_id, priority, payload, attempts, created_at "
                "FROM outbox WHERE acked = 0 AND next_attempt_at <= ? "
                "ORDER BY priority ASC, created_at ASC LIMIT ?",
                (now, limit),
            ).fetchall()
        return [
            SpoolItem(
                row_id=row[0],
                report_id=row[1],
                priority=Priority(
                    next(p for p, v in PRIORITY_ORDER.items() if v == row[2])
                ),
                payload=row[3],
                attempts=row[4],
                created_at=row[5],
            )
            for row in rows
        ]

    def purge(self, max_age_s: float, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM outbox WHERE acked = 1 OR (priority > 0 AND created_at < ?)",
                (now - max_age_s,),
            )
            self._db.commit()
            return cur.rowcount

    def enforce_limit(self, max_rows: int) -> int:
        """Drop oldest P1-P3 rows; P0 is never dropped."""
        if max_rows <= 0:
            return 0
        with self._lock:
            excess = int(
                self._db.execute(
                    "SELECT COUNT(*) FROM outbox WHERE acked = 0 AND priority > 0"
                ).fetchone()[0]
            ) - max_rows
            if excess <= 0:
                return 0
            cur = self._db.execute(
                "DELETE FROM outbox WHERE id IN ("
                " SELECT id FROM outbox WHERE acked = 0 AND priority > 0"
                " ORDER BY created_at ASC LIMIT ?)",
                (excess,),
            )
            self._db.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._db.close()
