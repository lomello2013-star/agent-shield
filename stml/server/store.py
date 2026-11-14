"""SQLite storage for the STML Fleet Core MVP.

Single-tenant, local-first. The interface is intentionally small so a PostgreSQL
adapter can replace it without touching HTTP handlers.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from stml.connector.security import restrict


@dataclass(frozen=True)
class Agent:
    id: str
    tenant_id: str
    hostname: str
    os: str
    arch: str
    agent_version: str
    status: str
    last_seen: float
    enrolled_at: float
    isolated: bool
    policy_version: str | None
    pubkey: str


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, hostname TEXT NOT NULL,
                os TEXT NOT NULL, arch TEXT NOT NULL, agent_version TEXT NOT NULL,
                status TEXT NOT NULL, last_seen REAL NOT NULL, enrolled_at REAL NOT NULL,
                isolated INTEGER NOT NULL DEFAULT 0, policy_version TEXT, pubkey TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, priority TEXT NOT NULL,
                kind TEXT NOT NULL, payload TEXT NOT NULL, created_at REAL NOT NULL,
                ack_at REAL
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL,
                action TEXT NOT NULL, target TEXT NOT NULL, prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS enrol_tokens (
                token TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, created_at REAL NOT NULL,
                used_at REAL
            );
            CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY, seen_at REAL NOT NULL
            );
            """
        )
        self._db.commit()
        restrict(self.path)

    # -- enrolment -------------------------------------------------------
    def create_enrol_token(self, tenant_id: str, token: str | None = None) -> str:
        token = token or secrets.token_urlsafe(24)
        with self._lock:
            self._db.execute(
                "INSERT INTO enrol_tokens(token, tenant_id, created_at) VALUES (?, ?, ?)",
                (token, tenant_id, time.time()),
            )
            self._db.commit()
        return token

    def enrol(self, token: str, tenant_id: str, hostname: str, os_name: str,
              arch: str, agent_version: str, pubkey: str) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT tenant_id, used_at FROM enrol_tokens WHERE token = ?", (token,)
            ).fetchone()
            if row is None or row["used_at"] is not None or row["tenant_id"] != tenant_id:
                raise PermissionError("invalid or used enrolment token")
            agent_id = str(uuid.uuid4())
            now = time.time()
            self._db.execute(
                "INSERT INTO agents(id, tenant_id, hostname, os, arch, agent_version, "
                "status, last_seen, enrolled_at, pubkey) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (agent_id, tenant_id, hostname, os_name, arch, agent_version,
                 "healthy", now, now, pubkey),
            )
            self._db.execute("UPDATE enrol_tokens SET used_at = ? WHERE token = ?", (now, token))
            self._db.commit()
        self._audit("agent", "enrol", agent_id)
        return agent_id

    # -- runtime ---------------------------------------------------------
    def agent(self, agent_id: str) -> Agent | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        return self._agent(row) if row else None

    def agents(self, tenant_id: str | None = None) -> list[Agent]:
        with self._lock:
            if tenant_id:
                rows = self._db.execute(
                    "SELECT * FROM agents WHERE tenant_id = ? ORDER BY hostname", (tenant_id,)
                ).fetchall()
            else:
                rows = self._db.execute("SELECT * FROM agents ORDER BY hostname").fetchall()
        return [self._agent(r) for r in rows]

    @staticmethod
    def _agent(row: sqlite3.Row) -> Agent:
        return Agent(
            id=row["id"], tenant_id=row["tenant_id"], hostname=row["hostname"],
            os=row["os"], arch=row["arch"], agent_version=row["agent_version"],
            status=row["status"], last_seen=row["last_seen"], enrolled_at=row["enrolled_at"],
            isolated=bool(row["isolated"]), policy_version=row["policy_version"],
            pubkey=row["pubkey"],
        )

    def heartbeat(self, agent_id: str, status: str, health: dict[str, Any]) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT status, isolated FROM agents WHERE id = ?", (agent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(agent_id)
            self._db.execute(
                "UPDATE agents SET status = ?, last_seen = ? WHERE id = ?",
                (status, time.time(), agent_id),
            )
            self._db.commit()
            changed = row["status"] != status
            isolated = bool(row["isolated"])
        if changed:
            self._audit("agent", "status_change", agent_id)
        return isolated

    def inventory(self, agent_id: str, fields: dict[str, Any]) -> None:
        allowed = {"os", "arch", "agent_version", "policy_version"}
        sets = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if not sets:
            return
        with self._lock:
            assignments = ", ".join(f"{k} = ?" for k in sets)
            cur = self._db.execute(
                f"UPDATE agents SET {assignments}, last_seen = ? WHERE id = ?",
                (*sets.values(), time.time(), agent_id),
            )
            self._db.commit()
        if cur.rowcount == 0:
            raise KeyError(agent_id)

    def isolate(self, agent_id: str, isolated: bool) -> None:
        with self._lock:
            cur = self._db.execute(
                "UPDATE agents SET isolated = ? WHERE id = ?", (1 if isolated else 0, agent_id)
            )
            self._db.commit()
        if cur.rowcount == 0:
            raise KeyError(agent_id)
        self._audit("operator", "isolate" if isolated else "resume", agent_id)

    # -- reports ---------------------------------------------------------
    def ingest(self, reports: Iterable[dict[str, Any]]) -> list[str]:
        acked: list[str] = []
        p0: list[str] = []
        with self._lock:
            for report in reports:
                rid = report.get("report_id")
                if not isinstance(rid, str) or not rid:
                    continue
                try:
                    self._db.execute(
                        "INSERT INTO reports(report_id, tenant_id, agent_id, priority, kind, "
                        "payload, created_at, ack_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (rid, report.get("tenant_id", ""), report.get("agent_id", ""),
                         report.get("priority", "P3"), report.get("kind", ""),
                         json.dumps(report.get("payload", {})), time.time(), time.time()),
                    )
                    acked.append(rid)
                    if report.get("priority") == "P0":
                        p0.append(rid)
                except sqlite3.IntegrityError:
                    acked.append(rid)  # idempotent
            self._db.commit()
        for rid in p0:
            self._audit("connector", "report_p0", rid)
        return acked

    def reports(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT report_id, tenant_id, agent_id, priority, kind, created_at "
                "FROM reports ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # -- replay ----------------------------------------------------------
    def seen_nonce(self, nonce: str) -> bool:
        with self._lock:
            try:
                self._db.execute("INSERT INTO nonces(nonce, seen_at) VALUES (?, ?)",
                                 (nonce, time.time()))
                self._db.commit()
                return False
            except sqlite3.IntegrityError:
                return True

    # -- audit chain -----------------------------------------------------
    def _audit(self, actor: str, action: str, target: str) -> None:
        with self._lock:
            prev = self._db.execute(
                "SELECT hash FROM audit ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = prev["hash"] if prev else "0" * 64
            ts = time.time()
            body = json.dumps({"ts": ts, "actor": actor, "action": action,
                               "target": target, "prev": prev_hash},
                              sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(body).hexdigest()
            self._db.execute(
                "INSERT INTO audit(ts, actor, action, target, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ts, actor, action, target, prev_hash, digest),
            )
            self._db.commit()

    def verify_audit(self) -> bool:
        with self._lock:
            rows = self._db.execute("SELECT * FROM audit ORDER BY id").fetchall()
        prev = "0" * 64
        for row in rows:
            body = json.dumps({"ts": row["ts"], "actor": row["actor"],
                               "action": row["action"], "target": row["target"],
                               "prev": row["prev_hash"]},
                              sort_keys=True, separators=(",", ":")).encode()
            if row["prev_hash"] != prev or hashlib.sha256(body).hexdigest() != row["hash"]:
                return False
            prev = row["hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self._db.close()
