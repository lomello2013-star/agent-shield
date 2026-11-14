"""Connector service: agent RPC + `*.jsonl` fallback -> `stml/v0` reports."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from stml.contracts.v0 import (
    AgentStatus,
    Heartbeat,
    Inventory,
    Priority,
    Report,
    utcnow,
)
from stml.connector.agent_client import AgentClient, AgentUnavailable
from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.security import restrict
from stml.connector.transport import Transport


@dataclass
class ConnectorConfig:
    tenant_id: str = "default"
    agent_id: str = ""
    connector_id: str = ""
    data_root: str = "."
    heartbeat_interval_s: float = 10.0
    inventory_interval_s: float = 30.0
    spool_path: str = "stml-connector.sqlite3"
    state_path: str = "stml-connector-state.json"
    max_batch: int = 50
    max_backoff_s: float = 300.0
    extra: dict[str, Any] = field(default_factory=dict)


class Connector:
    def __init__(
        self,
        config: ConnectorConfig,
        agent: AgentClient | None,
        spool: Spool,
        tailer: JsonlTailer,
        transport: Transport,
    ) -> None:
        self.config = config
        self.agent = agent
        self.spool = spool
        self.tailer = tailer
        self.transport = transport
        self._load_state()
        self.last_heartbeat: Heartbeat | None = None
        self.last_inventory: Inventory | None = None
        self.last_error: str | None = None
        self._last_inventory_at = 0.0

    # -- identity --------------------------------------------------------
    def _load_state(self) -> None:
        path = Path(self.config.state_path)
        state: dict[str, str] = {}
        if path.exists():
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                state = {}
        self.config.agent_id = self.config.agent_id or state.get("agent_id") or str(uuid.uuid4())
        self.config.connector_id = self.config.connector_id or state.get("connector_id") or str(uuid.uuid4())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"agent_id": self.config.agent_id,
                        "connector_id": self.config.connector_id,
                        "tenant_id": self.config.tenant_id}, indent=2),
            encoding="utf-8",
        )
        restrict(path)

    # -- read-only RPC bridge (S0.1b) ------------------------------------
    def rpc_health(self) -> dict[str, Any]:
        return self._agent_call("health")

    def rpc_stats(self) -> dict[str, Any]:
        return self._agent_call("stats")

    def rpc_self_test(self) -> dict[str, Any]:
        return self._agent_call("self_test")

    def rpc_immutable_check(self) -> dict[str, Any]:
        return self._agent_call("immutable_check")

    def _agent_call(self, method: str) -> dict[str, Any]:
        if self.agent is None:
            raise AgentUnavailable(f"{method}: no agent configured")
        return getattr(self.agent, method)()

    def _base(self) -> dict[str, Any]:
        return {
            "tenant_id": self.config.tenant_id,
            "agent_id": self.config.agent_id,
            "connector_id": self.config.connector_id,
            "message_id": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex,
        }

    # -- collection ------------------------------------------------------
    def heartbeat(self) -> Heartbeat:
        health: dict[str, Any] = {}
        source = "rpc"
        status = AgentStatus.UNKNOWN
        if self.agent is not None:
            try:
                health = self.agent.health() or {}
                status = self._status_from_health(health)
            except AgentUnavailable as exc:
                self.last_error = str(exc)
                source = "files"
                status = AgentStatus.OFFLINE
        else:
            source = "files"
        hb = Heartbeat(**self._base(), status=status, health=health, source=source)
        self.last_heartbeat = hb
        return hb

    def inventory(self) -> Inventory:
        stats: dict[str, Any] = {}
        immutable_ok: bool | None = None
        source = "rpc"
        if self.agent is not None:
            try:
                stats = self.agent.stats() or {}
                immutable_ok = bool(self.agent.immutable_check().get("immutable") == "ok")
            except AgentUnavailable as exc:
                self.last_error = str(exc)
                source = "files"
        else:
            source = "files"
        inv = Inventory(
            **self._base(),
            os=str(stats.get("os", "unknown")),
            arch=str(stats.get("arch", "unknown")),
            agent_version=str(stats.get("version", "unknown")),
            rules_version=stats.get("rules_version"),
            model_version=stats.get("model_version"),
            capabilities=["health", "stats", "immutable_check"],
            immutable_ok=immutable_ok,
            source=source,
        )
        self.last_inventory = inv
        self._last_inventory_at = time.time()
        return inv

    @staticmethod
    def _status_from_health(health: dict[str, Any]) -> AgentStatus:
        raw = str(health.get("status", "healthy")).lower()
        if health.get("safe_mode"):
            return AgentStatus.SAFE_MODE
        if raw in {"healthy", "ok", "running"}:
            return AgentStatus.HEALTHY
        if raw in {"degraded", "safe", "safe_mode"}:
            return AgentStatus.DEGRADED
        return AgentStatus.UNKNOWN

    # -- reports ---------------------------------------------------------
    def _paths(self) -> list[Path]:
        root = Path(self.config.data_root)
        return [root / "spool" / "events.jsonl",
                root / "audit" / "chain.jsonl",
                root / "quarantine.jsonl"]

    def collect_reports(self) -> int:
        added = 0
        for record in self.tailer.read_all(self._paths()):
            report = self._to_report(record)
            if self.spool.enqueue(report):
                added += 1
        return added

    def _to_report(self, record: dict[str, Any]) -> Report:
        kind = str(record.get("kind") or record.get("event") or "agent.record")
        raw_priority = str(record.get("priority", "")).upper()
        if raw_priority in {"P0", "P1", "P2", "P3"}:
            priority = Priority(raw_priority)
        elif record.get("severity") in {"critical", "high"} or "incident" in kind:
            priority = Priority.P1
        elif "quarantine" in kind or "audit" in kind:
            priority = Priority.P3
        else:
            priority = Priority.P2
        report_id = str(record.get("report_id") or "")
        if not report_id:
            blob = json.dumps(record, sort_keys=True, ensure_ascii=False).encode()
            report_id = "r-" + hashlib.sha256(blob).hexdigest()[:24]
        return Report(
            **self._base(),
            report_id=report_id,
            priority=priority,
            kind=kind,
            payload=record,
            created_at=utcnow(),
        )

    # -- delivery --------------------------------------------------------
    def flush(self) -> int:
        batch = self.spool.peek(limit=self.config.max_batch)
        if not batch:
            return 0
        try:
            acked = set(self.transport.send([item.report() for item in batch]))
        except Exception as exc:  # noqa: BLE001 - buffered, retried later
            self.last_error = f"transport: {exc}"
            for item in batch:
                delay = min(self.config.max_backoff_s, 2 ** min(item.attempts, 8))
                self.spool.mark_attempt(item.row_id, item.attempts + 1, delay)
            return 0
        for item in batch:
            if item.report_id not in acked:
                delay = min(self.config.max_backoff_s, 2 ** min(item.attempts, 8))
                self.spool.mark_attempt(item.row_id, item.attempts + 1, delay)
        return self.spool.ack(list(acked))

    # -- loop ------------------------------------------------------------
    def tick(self) -> None:
        self.heartbeat()
        if time.time() - self._last_inventory_at >= self.config.inventory_interval_s:
            self.inventory()
        self.collect_reports()
        self.flush()

    def status(self) -> dict[str, Any]:
        return {
            "tenant_id": self.config.tenant_id,
            "agent_id": self.config.agent_id,
            "connector_id": self.config.connector_id,
            "heartbeat": self.last_heartbeat.model_dump(mode="json") if self.last_heartbeat else None,
            "inventory": self.last_inventory.model_dump(mode="json") if self.last_inventory else None,
            "spool_pending": self.spool.pending_count(),
            "spool_p0": self.spool.p0_count(),
            "last_error": self.last_error,
            "tailer_skipped": self.tailer.skipped,
        }

    def run(self, once: bool = False, max_ticks: int | None = None) -> None:
        ticks = 0
        while True:
            self.tick()
            self.spool.purge(max_age_s=7 * 24 * 3600)
            self.spool.enforce_limit(max_rows=10_000)
            ticks += 1
            if once or (max_ticks is not None and ticks >= max_ticks):
                return
            time.sleep(self.config.heartbeat_interval_s)
