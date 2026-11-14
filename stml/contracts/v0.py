"""`stml/v0` wire contracts.

These models are the frozen boundary between the Agent Connector and the STML
server. The connector reads the existing agent (`core/ipc.py`, `*.jsonl`) and
emits only these messages; pickle never crosses this boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "stml/v0"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Priority(str, Enum):
    P0 = "P0"  # incident: never dropped
    P1 = "P1"  # alert / heartbeat anomaly
    P2 = "P2"  # feedback
    P3 = "P3"  # telemetry / audit


class AgentStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    SAFE_MODE = "safe_mode"
    UNKNOWN = "unknown"


class Envelope(BaseModel):
    """Fields common to every connector -> server message."""

    schema_version: Literal["stml/v0"] = SCHEMA_VERSION
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    connector_id: str = Field(min_length=1)
    message_id: str = Field(min_length=1)
    sent_at: datetime = Field(default_factory=utcnow)
    nonce: str = Field(min_length=8)
    signature: str | None = None

    @field_validator("sent_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("sent_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class EnrolRequest(BaseModel):
    schema_version: Literal["stml/v0"] = SCHEMA_VERSION
    tenant_id: str
    hostname: str
    os: str
    arch: str
    agent_version: str
    connector_version: str
    capabilities: list[str] = Field(default_factory=list)
    enrolment_token: str = Field(min_length=8)


class EnrolResponse(BaseModel):
    schema_version: Literal["stml/v0"] = SCHEMA_VERSION
    agent_id: str
    tenant_id: str
    server_time: datetime = Field(default_factory=utcnow)
    heartbeat_interval_s: int = 10
    inventory_interval_s: int = 30
    accepted: bool = True


class Heartbeat(Envelope):
    status: AgentStatus
    agent_uptime_s: float | None = None
    health: dict[str, Any] = Field(default_factory=dict)
    counters: dict[str, int] = Field(default_factory=dict)
    source: Literal["rpc", "files", "mixed"] = "rpc"


class Inventory(Envelope):
    os: str
    arch: str
    agent_version: str
    rules_version: str | None = None
    model_version: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    quarantine_entries: int | None = None
    immutable_ok: bool | None = None
    source: Literal["rpc", "files", "mixed"] = "rpc"


class Report(Envelope):
    report_id: str = Field(min_length=1)
    priority: Priority
    kind: str = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    attempts: int = 0


class Ack(BaseModel):
    schema_version: Literal["stml/v0"] = SCHEMA_VERSION
    acked: list[str] = Field(default_factory=list)
    server_time: datetime = Field(default_factory=utcnow)


class ErrorBody(BaseModel):
    schema_version: Literal["stml/v0"] = SCHEMA_VERSION
    code: str
    message: str
    retryable: bool = False
    detail: dict[str, Any] = Field(default_factory=dict)


class JsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcResponse(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: int | str | None = None
    result: Any | None = None
    error: ErrorBody | None = None


PRIORITY_ORDER = {Priority.P0: 0, Priority.P1: 1, Priority.P2: 2, Priority.P3: 3}
