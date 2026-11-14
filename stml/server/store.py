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
            CREATE TABLE IF NOT EXISTS commands (
                command_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, kind TEXT NOT NULL,
                payload TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL,
                acked_at REAL, result TEXT
            );
            CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT NOT NULL, version TEXT NOT NULL, channel TEXT NOT NULL,
                content TEXT NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL,
                created_at REAL NOT NULL, tenant_id TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (tenant_id, policy_id, version)
            );
            CREATE TABLE IF NOT EXISTS rollouts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, policy_id TEXT NOT NULL,
                version TEXT NOT NULL, percent INTEGER NOT NULL, status TEXT NOT NULL,
                created_at REAL NOT NULL, updated_at REAL NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS rollout_agents (
                rollout_id INTEGER NOT NULL, agent_id TEXT NOT NULL,
                old_version TEXT, PRIMARY KEY (rollout_id, agent_id)
            );
            CREATE TABLE IF NOT EXISTS keys (
                key_id TEXT PRIMARY KEY, key_class TEXT NOT NULL, public_pem TEXT NOT NULL,
                private_path TEXT NOT NULL, created_at REAL NOT NULL, revoked_at REAL,
                rotated_from TEXT
            );
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                target TEXT NOT NULL, payload TEXT NOT NULL, proposed_by TEXT NOT NULL,
                status TEXT NOT NULL, created_at REAL NOT NULL, decided_by TEXT,
                decided_at REAL, tenant_id TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL,
                payload TEXT NOT NULL, consent INTEGER NOT NULL, received_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL UNIQUE,
                report_id TEXT NOT NULL, label TEXT NOT NULL, holdout INTEGER NOT NULL,
                features TEXT NOT NULL, created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS models (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                version TEXT NOT NULL, metrics TEXT NOT NULL, signature TEXT NOT NULL,
                key_id TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL,
                activated_at REAL, UNIQUE(name, version)
            );
            CREATE TABLE IF NOT EXISTS model_state (
                key TEXT PRIMARY KEY, value TEXT
            );
            CREATE TABLE IF NOT EXISTS revoked_certs (
                serial TEXT PRIMARY KEY, revoked_at REAL NOT NULL, reason TEXT
            );
            """
        )
        self._db.commit()
        self._migrate_columns()
        restrict(self.path)

    def _migrate_columns(self) -> None:
        """Add tenant columns to databases created by earlier STML snapshots."""
        for table in ("policies", "approvals", "rollouts"):
            columns = [row[1] for row in self._db.execute(f"PRAGMA table_info({table})")]
            if "tenant_id" not in columns:
                self._db.execute(
                    f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''")
        self._db.commit()

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
        self.enqueue_command(agent_id, "isolate", {"isolated": isolated})

    # -- commands ---------------------------------------------------------
    def enqueue_command(self, agent_id: str, kind: str,
                        payload: dict[str, Any] | None = None) -> dict[str, Any]:
        command_id = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            self._db.execute(
                "INSERT INTO commands(command_id, agent_id, kind, payload, status, created_at) "
                "VALUES (?, ?, ?, ?, 'pending', ?)",
                (command_id, agent_id, kind,
                 json.dumps(payload or {}, ensure_ascii=False), now))
            self._db.commit()
        self._audit("operator", "command_enqueue", f"{agent_id}:{kind}")
        return {"command_id": command_id, "agent_id": agent_id, "kind": kind,
                "payload": payload or {}, "status": "pending", "created_at": now}

    def pending_commands(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM commands WHERE agent_id = ? AND status = 'pending' "
                "ORDER BY created_at", (agent_id,)).fetchall()
        return [{"command_id": row["command_id"], "kind": row["kind"],
                 "payload": json.loads(row["payload"]), "status": row["status"],
                 "created_at": row["created_at"]} for row in rows]

    def ack_command(self, agent_id: str, command_id: str, status: str = "acked",
                    result: dict[str, Any] | None = None) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            cur = self._db.execute(
                "UPDATE commands SET status = ?, acked_at = ?, result = ? "
                "WHERE command_id = ? AND agent_id = ?",
                (status, now, json.dumps(result or {}, ensure_ascii=False),
                 command_id, agent_id))
            self._db.commit()
        if cur.rowcount == 0:
            raise KeyError(command_id)
        self._audit("agent", f"command_{status}", f"{agent_id}:{command_id}")
        return {"command_id": command_id, "status": status}

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

    # -- policies / rollout ---------------------------------------------
    def add_policy(self, policy: dict[str, Any]) -> None:
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO policies(policy_id, version, channel, content, key_id, "
                    "signature, created_at, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (policy["policy_id"], policy["version"], policy.get("channel", "stable"),
                     json.dumps(policy.get("content", {})), policy.get("key_id", ""),
                     policy.get("signature", ""), time.time(), policy.get("tenant_id", "")),
                )
                self._db.commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError("policy version already exists") from exc
        self._audit("operator", "policy_add", f"{policy['policy_id']}@{policy['version']}")

    def policies(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if tenant_id is None:
                rows = self._db.execute(
                    "SELECT policy_id, version, channel, key_id, created_at, tenant_id "
                    "FROM policies ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT policy_id, version, channel, key_id, created_at, tenant_id "
                    "FROM policies WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)
                ).fetchall()
        return [dict(r) for r in rows]

    def policy(self, policy_id: str, version: str,
               tenant_id: str | None = None) -> dict[str, Any] | None:
        with self._lock:
            if tenant_id is None:
                row = self._db.execute(
                    "SELECT * FROM policies WHERE policy_id = ? AND version = ?",
                    (policy_id, version),
                ).fetchone()
            else:
                row = self._db.execute(
                    "SELECT * FROM policies WHERE policy_id = ? AND version = ? AND tenant_id = ?",
                    (policy_id, version, tenant_id),
                ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["content"] = json.loads(data["content"])
        return data

    def dry_run(self, policy_id: str, version: str,
                agent_ids: list[str] | None = None,
                tenant_id: str | None = None) -> dict[str, Any]:
        policy = self.policy(policy_id, version, tenant_id)
        if policy is None:
            raise KeyError("unknown policy")
        agents = self.agents(tenant_id)
        if agent_ids:
            wanted = set(agent_ids)
            agents = [a for a in agents if a.id in wanted]
        changes = [
            {"agent_id": a.id, "from": a.policy_version, "to": version}
            for a in agents if a.policy_version != version
        ]
        return {"policy_id": policy_id, "version": version, "channel": policy["channel"],
                "agents": len(agents), "would_change": len(changes), "changes": changes}

    def start_rollout(self, policy_id: str, version: str, percent: int = 1,
                      tenant_id: str | None = None) -> dict[str, Any]:
        policy = self.policy(policy_id, version, tenant_id)
        if policy is None:
            raise KeyError("unknown policy")
        percent = max(0, min(100, int(percent)))
        agents = self.agents(tenant_id)
        count = 0 if percent == 0 else max(1, (len(agents) * percent + 99) // 100)
        selected = agents[:count]
        now = time.time()
        status = "completed" if percent >= 100 else "running"
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO rollouts(policy_id, version, percent, status, created_at, updated_at, "
                "tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (policy_id, version, percent, status, now, now, policy.get("tenant_id", "")),
            )
            rollout_id = int(cur.lastrowid)
            for agent in selected:
                self._db.execute(
                    "INSERT OR REPLACE INTO rollout_agents(rollout_id, agent_id, old_version) "
                    "VALUES (?, ?, ?)", (rollout_id, agent.id, agent.policy_version),
                )
                self._db.execute("UPDATE agents SET policy_version = ? WHERE id = ?",
                                 (version, agent.id))
            self._db.commit()
        self._audit("operator", "rollout_start", f"{policy_id}@{version}:{percent}%")
        return {"rollout_id": rollout_id, "policy_id": policy_id, "version": version,
                "percent": percent, "applied": [a.id for a in selected], "status": status}

    def promote_rollout(self, rollout_id: int) -> dict[str, Any]:
        stages = (1, 10, 50, 100)
        with self._lock:
            row = self._db.execute("SELECT * FROM rollouts WHERE id = ?", (rollout_id,)).fetchone()
            if row is None:
                raise KeyError("unknown rollout")
            if row["status"] != "running":
                raise ValueError("rollout is not running")
            current = int(row["percent"])
            next_percent = next((s for s in stages if s > current), 100)
            agents = self._db.execute(
                "SELECT id, policy_version FROM agents WHERE tenant_id = ? ORDER BY hostname",
                (row["tenant_id"],),
            ).fetchall()
            target = max(1, (len(agents) * next_percent + 99) // 100)
            applied = {r["agent_id"] for r in self._db.execute(
                "SELECT agent_id FROM rollout_agents WHERE rollout_id = ?", (rollout_id,))}
            newly: list[str] = []
            for agent in agents[:target]:
                if agent["id"] in applied:
                    continue
                self._db.execute(
                    "INSERT OR REPLACE INTO rollout_agents(rollout_id, agent_id, old_version) "
                    "VALUES (?, ?, ?)", (rollout_id, agent["id"], agent["policy_version"]))
                self._db.execute("UPDATE agents SET policy_version = ? WHERE id = ?",
                                 (row["version"], agent["id"]))
                newly.append(agent["id"])
            status = "completed" if next_percent >= 100 else "running"
            self._db.execute(
                "UPDATE rollouts SET percent = ?, status = ?, updated_at = ? WHERE id = ?",
                (next_percent, status, time.time(), rollout_id))
            self._db.commit()
        self._audit("operator", "rollout_promote", f"{rollout_id}:{next_percent}%")
        return {"rollout_id": rollout_id, "percent": next_percent, "status": status,
                "applied": newly}

    def rollout(self, rollout_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM rollouts WHERE id = ?", (rollout_id,)).fetchone()
            agents = self._db.execute(
                "SELECT agent_id, old_version FROM rollout_agents WHERE rollout_id = ?",
                (rollout_id,),
            ).fetchall()
        if row is None:
            return None
        data = dict(row)
        data["agents"] = [dict(a) for a in agents]
        return data

    def halt_rollout(self, rollout_id: int) -> None:
        with self._lock:
            cur = self._db.execute(
                "UPDATE rollouts SET status = 'halted', updated_at = ? WHERE id = ? AND status = 'running'",
                (time.time(), rollout_id),
            )
            self._db.commit()
        if cur.rowcount == 0:
            raise KeyError("unknown or finished rollout")
        self._audit("operator", "rollout_halt", str(rollout_id))

    def rollback_rollout(self, rollout_id: int) -> None:
        with self._lock:
            row = self._db.execute("SELECT status FROM rollouts WHERE id = ?",
                                   (rollout_id,)).fetchone()
            if row is None:
                raise KeyError("unknown rollout")
            agents = self._db.execute(
                "SELECT agent_id, old_version FROM rollout_agents WHERE rollout_id = ?",
                (rollout_id,),
            ).fetchall()
            for agent in agents:
                self._db.execute("UPDATE agents SET policy_version = ? WHERE id = ?",
                                 (agent["old_version"], agent["agent_id"]))
            self._db.execute("UPDATE rollouts SET status = 'rolled_back', updated_at = ? WHERE id = ?",
                             (time.time(), rollout_id))
            self._db.commit()
        self._audit("operator", "rollout_rollback", str(rollout_id))

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

    # -- trust: keys / approvals -----------------------------------------
    def add_key(self, key_id: str, key_class: str, public_pem: str,
                private_path: str, rotated_from: str | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO keys(key_id, key_class, public_pem, private_path, "
                "created_at, rotated_from) VALUES (?, ?, ?, ?, ?, ?)",
                (key_id, key_class, public_pem, private_path, time.time(), rotated_from),
            )
            self._db.commit()
        self._audit("trust", "key_create", f"{key_class}:{key_id}")

    def keys(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT key_id, key_class, public_pem, private_path, created_at, "
                "revoked_at, rotated_from FROM keys ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def key(self, key_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,)).fetchone()
        return dict(row) if row else None

    def revoke_key(self, key_id: str) -> None:
        with self._lock:
            cur = self._db.execute(
                "UPDATE keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                (time.time(), key_id),
            )
            self._db.commit()
        if cur.rowcount == 0:
            raise KeyError("unknown or already revoked key")
        self._audit("trust", "key_revoke", key_id)

    def propose_approval(self, kind: str, target: str, payload: dict[str, Any],
                         proposed_by: str, tenant_id: str = "") -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO approvals(kind, target, payload, proposed_by, status, created_at, "
                "tenant_id) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                (kind, target, json.dumps(payload), proposed_by, time.time(), tenant_id),
            )
            self._db.commit()
            approval_id = int(cur.lastrowid)
        self._audit("operator", "approval_propose", f"{kind}:{target}")
        return approval_id

    def approvals(self, status: str | None = None,
                  tenant_id: str | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._db.execute(
                f"SELECT * FROM approvals{where} ORDER BY id DESC", params
            ).fetchall()
        return [dict(r) for r in rows]

    def approval(self, approval_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM approvals WHERE id = ?",
                                   (approval_id,)).fetchone()
        return dict(row) if row else None

    def decide_approval(self, approval_id: int, status: str, decided_by: str) -> None:
        if status not in {"approved", "rejected"}:
            raise ValueError("status must be approved|rejected")
        with self._lock:
            cur = self._db.execute(
                "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (status, decided_by, time.time(), approval_id),
            )
            self._db.commit()
        if cur.rowcount == 0:
            raise KeyError("unknown or already decided approval")
        self._audit("approver", f"approval_{status}", str(approval_id))

    def is_approved(self, kind: str, target: str,
                    tenant_id: str | None = None) -> bool:
        with self._lock:
            if tenant_id is None:
                row = self._db.execute(
                    "SELECT 1 FROM approvals WHERE kind = ? AND target = ? AND status = 'approved' "
                    "ORDER BY id DESC LIMIT 1", (kind, target),
                ).fetchone()
            else:
                row = self._db.execute(
                    "SELECT 1 FROM approvals WHERE kind = ? AND target = ? AND status = 'approved' "
                    "AND tenant_id = ? ORDER BY id DESC LIMIT 1", (kind, target, tenant_id),
                ).fetchone()
        return row is not None

    def operator_metrics(self, window_s: float = 7 * 24 * 3600) -> dict[str, Any]:
        cutoff = time.time() - window_s
        with self._lock:
            rows = self._db.execute(
                "SELECT action, COUNT(*) AS n FROM audit "
                "WHERE actor = 'operator' AND ts >= ? GROUP BY action", (cutoff,)
            ).fetchall()
        counts = {r["action"]: int(r["n"]) for r in rows}
        actions = sum(counts.values())
        reversals = sum(counts.get(a, 0) for a in
                        ("rollout_rollback", "rollout_halt", "model_rollback"))
        sufficient = actions >= 50
        return {
            "window_s": window_s,
            "actions": actions,
            "reversals": reversals,
            "s18": round(reversals / actions, 4) if sufficient else None,
            "s19": None,  # operator-attributed incidents are not tracked yet
            "sufficient_data": sufficient,
            "by_action": counts,
        }

    def audit_export(self, limit: int = 1000) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, actor, action, target, prev_hash, hash FROM audit "
                "ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, int]:
        with self._lock:
            def one(sql: str) -> int:
                return int(self._db.execute(sql).fetchone()[0])
            return {
                "agents": one("SELECT COUNT(*) FROM agents"),
                "healthy": one("SELECT COUNT(*) FROM agents WHERE status = 'healthy'"),
                "degraded": one("SELECT COUNT(*) FROM agents WHERE status = 'degraded'"),
                "offline": one("SELECT COUNT(*) FROM agents WHERE status = 'offline'"),
                "isolated": one("SELECT COUNT(*) FROM agents WHERE isolated = 1"),
                "reports": one("SELECT COUNT(*) FROM reports"),
                "p0_reports": one("SELECT COUNT(*) FROM reports WHERE priority = 'P0'"),
                "approvals_pending": one("SELECT COUNT(*) FROM approvals WHERE status = 'pending'"),
                "policies": one("SELECT COUNT(*) FROM policies"),
                "models": one("SELECT COUNT(*) FROM models"),
                "telemetry": one("SELECT COUNT(*) FROM telemetry"),
            }

    # -- learning: telemetry / cases / models ---------------------------
    def add_telemetry(self, agent_id: str, events: list[dict[str, Any]]) -> int:
        now = time.time()
        with self._lock:
            for event in events:
                self._db.execute(
                    "INSERT INTO telemetry(agent_id, payload, consent, received_at) "
                    "VALUES (?, ?, 1, ?)",
                    (agent_id, json.dumps(event), now),
                )
            self._db.commit()
        return len(events)

    def telemetry(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, agent_id, payload, received_at FROM telemetry "
                "ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"id": r["id"], "agent_id": r["agent_id"],
                 "payload": json.loads(r["payload"]), "received_at": r["received_at"]}
                for r in rows]

    def purge_telemetry(self, max_age_s: float) -> int:
        with self._lock:
            cur = self._db.execute("DELETE FROM telemetry WHERE received_at < ?",
                                   (time.time() - max_age_s,))
            self._db.commit()
            return cur.rowcount

    def add_case(self, case_id: str, report_id: str, label: str,
                 holdout: bool, features: dict[str, Any]) -> None:
        if label not in {"TP", "FP"}:
            raise ValueError("label must be TP|FP")
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO cases(case_id, report_id, label, holdout, features, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (case_id, report_id, label, 1 if holdout else 0,
                     json.dumps(features), time.time()),
                )
                self._db.commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError("case_id already exists") from exc
        self._audit("operator", "case_add", f"{case_id}:{label}")

    def cases(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT case_id, report_id, label, holdout, features, created_at "
                "FROM cases ORDER BY id DESC"
            ).fetchall()
        return [{"case_id": r["case_id"], "report_id": r["report_id"],
                 "label": r["label"], "holdout": bool(r["holdout"]),
                 "features": json.loads(r["features"]), "created_at": r["created_at"]}
                for r in rows]

    def add_model(self, name: str, version: str, metrics: dict[str, Any],
                  signature: str, key_id: str) -> int:
        with self._lock:
            try:
                cur = self._db.execute(
                    "INSERT INTO models(name, version, metrics, signature, key_id, status, "
                    "created_at) VALUES (?, ?, ?, ?, ?, 'staged', ?)",
                    (name, version, json.dumps(metrics), signature, key_id, time.time()),
                )
                self._db.commit()
                return int(cur.lastrowid)
            except sqlite3.IntegrityError as exc:
                raise ValueError("model version already exists") from exc

    def models(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM models ORDER BY id DESC").fetchall()
        return [self._model(r) for r in rows]

    def model(self, model_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM models WHERE id = ?", (model_id,)).fetchone()
        return self._model(row) if row else None

    @staticmethod
    def _model(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["metrics"] = json.loads(data["metrics"])
        return data

    def set_model_status(self, model_id: int, status: str) -> None:
        with self._lock:
            self._db.execute("UPDATE models SET status = ? WHERE id = ?", (status, model_id))
            self._db.commit()

    def _model_state(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM model_state WHERE key = ?",
                                   (key,)).fetchone()
        return row["value"] if row else None

    def _set_model_state(self, key: str, value: str | None) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO model_state(key, value) VALUES (?, ?)",
                             (key, value))
            self._db.commit()

    def active_model(self) -> dict[str, Any] | None:
        active = self._model_state("active")
        return self.model(int(active)) if active else None

    def activate_model(self, model_id: int) -> dict[str, Any]:
        model = self.model(model_id)
        if model is None:
            raise KeyError("unknown model")
        previous = self._model_state("active")
        self._set_model_state("previous", previous)
        self._set_model_state("active", str(model_id))
        with self._lock:
            self._db.execute("UPDATE models SET status = 'active', activated_at = ? WHERE id = ?",
                             (time.time(), model_id))
            self._db.commit()
        self._audit("operator", "model_activate", str(model_id))
        return {"model_id": model_id, "previous": previous}

    def rollback_model(self) -> dict[str, Any]:
        previous = self._model_state("previous")
        if not previous:
            raise KeyError("no previous model")
        current = self._model_state("active")
        self._set_model_state("active", previous)
        self._set_model_state("previous", current)
        with self._lock:
            self._db.execute("UPDATE models SET status = 'rolled_back' WHERE id = ?",
                             (int(current) if current else -1,))
            self._db.execute("UPDATE models SET status = 'active' WHERE id = ?",
                             (int(previous),))
            self._db.commit()
        self._audit("operator", "model_rollback", previous)
        return {"active": int(previous), "rolled_back": current}

    # -- TLS client certificate revocation --------------------------------
    @staticmethod
    def _normalize_serial(serial: str) -> str:
        return serial.replace(":", "").replace(" ", "").upper().lstrip("0") or "0"

    def revoke_cert(self, serial: str, reason: str = "") -> None:
        serial = self._normalize_serial(serial)
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO revoked_certs(serial, revoked_at, reason) "
                "VALUES (?, ?, ?)", (serial, time.time(), reason),
            )
            self._db.commit()
        self._audit("operator", "cert_revoke", serial)

    def is_cert_revoked(self, serial: str) -> bool:
        serial = self._normalize_serial(serial)
        with self._lock:
            row = self._db.execute("SELECT 1 FROM revoked_certs WHERE serial = ?",
                                   (serial,)).fetchone()
        return row is not None

    def revoked_certs(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT serial, revoked_at, reason FROM revoked_certs ORDER BY revoked_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

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
