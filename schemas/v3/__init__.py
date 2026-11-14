"""Contracts v3.0 — normative schemas (docs/data-model-v3.md).

Policy: the core accepts ``3.x`` (backward-compatible additions) and rejects
``4.0`` with ``incompatible_schema``. Unknown *values* of open enums
(``category``, ``source``) are tolerated; handlers must ignore what they do not
know instead of crashing. ``platform_data`` is intentionally extensible.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "3.0"
SUPPORTED_MAJOR = 3

EVENT_CATEGORIES = (
    "process.start", "process.exit", "process.access",
    "file.create", "file.write", "file.exec", "file.delete", "file.read",
    "net.connect", "net.listen", "dns.query",
    "auth.success", "auth.failure", "priv.grant",
    "persistence.change", "module.load", "log.tamper",
    "registry.change", "memory.access", "defender.tamper",
    "script.execute", "config.change", "unknown",
)
KNOWN_EVENT_CATEGORIES = frozenset(EVENT_CATEGORIES)

SEVERITIES = ("info", "low", "medium", "high", "critical")
DETECTORS = ("rule", "file_model", "behavior_model", "memory_model", "net_model")
ACTION_TYPES = (
    "notify", "suspend", "resume", "block_network", "unblock_network",
    "quarantine", "restore", "terminate",
)
ACTION_STATUSES = ("pending", "approved", "rejected", "timeout", "executed", "failed")
DECISIONS = ("pending", "approved", "rejected", "timeout")
MODULE_STATUSES = ("ok", "degraded", "failed", "stopped")
PLATFORMS = ("windows", "linux")
LAYERS = ("kernel", "user", "script", "network", "memory")
CONFIRMATION_LEVELS = ("critical_system", "protected_dir", "normal")
CONFIRMED_BY = ("rule", "analyst", "sandbox", "ensemble", "intel")

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class IncompatibleSchemaError(ValueError):
    """Raised when a message/schema major version is not supported."""

    code = "incompatible_schema"


def parse_schema_version(value: str) -> tuple[int, int]:
    """Parse ``"3.1"`` -> ``(3, 1)``; raise IncompatibleSchemaError on garbage."""
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+", value):
        raise IncompatibleSchemaError(f"malformed schema_version: {value!r}")
    major, minor = value.split(".")
    return int(major), int(minor)


def check_schema_version(value: str) -> str:
    """Accept 3.x, reject everything else with `incompatible_schema`."""
    major, _minor = parse_schema_version(value)
    if major != SUPPORTED_MAJOR:
        raise IncompatibleSchemaError(
            f"incompatible_schema: {value} (core supports {SUPPORTED_MAJOR}.x)"
        )
    return value


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Actor(_Base):
    pid: int = Field(ge=0)
    ppid: int | None = Field(default=None, ge=0)
    name: str
    path: str
    cmdline_hash: str
    cmdline_redacted: str = ""
    uid: str | None = None
    sid: str | None = None
    session: int | None = None
    container_id: str | None = None
    signature: str | None = None
    sha256: str | None = None


class ObjectRef(_Base):
    type: str
    path: str
    sha256: str | None = None
    ip: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = None


class UserRef(_Base):
    name: str
    domain: str | None = None
    uid: str | None = None
    sid_hash: str | None = None


class HostInfo(_Base):
    host_id: str
    os: str
    version: str
    arch: str
    kernel: str | None = None


class IntegrityInfo(_Base):
    level: str
    signature: str | None = None
    verified: bool


class PiiFlags(_Base):
    paths_hashed: bool = True
    cmdline_hashed: bool = True
    usernames_hashed: bool = True
    ips_hashed: bool = False


class KernelMeta(_Base):
    irql: int | None = Field(default=None, ge=0)
    callback_type: str | None = None
    trust: str | None = None


class Event(_Base):
    schema_version: str = SCHEMA_VERSION
    event_id: UUID
    trace_id: UUID
    ts_event: datetime
    ts_ingest: datetime
    platform: Literal["windows", "linux"]
    source: str
    layer: Literal["kernel", "user", "script", "network", "memory"]
    category: str                     # open enum: unknown values are tolerated
    action: str
    actor: Actor | None = None
    object: ObjectRef | None = None
    user: UserRef | None = None
    host: HostInfo
    integrity: IntegrityInfo | None = None
    raw_ref: str
    pii: PiiFlags = Field(default_factory=PiiFlags)
    platform_data: dict[str, Any] = Field(default_factory=dict)
    kernel_meta: KernelMeta | None = None

    @field_validator("schema_version")
    @classmethod
    def _version(cls, v: str) -> str:
        return check_schema_version(v)


class Verdict(_Base):
    verdict_id: UUID
    trace_id: UUID
    event_id: UUID
    detector: Literal["rule", "file_model", "behavior_model", "memory_model", "net_model"]
    rule_id: str | None = None
    model_id: str | None = None
    model_version: str | None = None
    platform: Literal["windows", "linux"]
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Literal["info", "low", "medium", "high", "critical"]
    reason_code: str
    reason_text: str
    actor_pid: int | None = None      # process-targeted actions (suspend/resume)
    object_path: str | None = None    # file-targeted actions (quarantine)
    event_ts: datetime | None = None  # source-event time, for attribution


class RollbackRef(_Base):
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)


class Action(_Base):
    action_id: UUID
    trace_id: UUID
    verdict_id: UUID
    type: Literal["notify", "suspend", "resume", "block_network", "unblock_network",
                  "quarantine", "restore", "terminate"]
    target: str
    reversible: bool
    requires_confirmation: bool
    confirmation_id: UUID | None = None
    status: Literal["pending", "approved", "rejected", "timeout", "executed", "failed"] = "pending"
    platform_effect: str = ""
    rollback: RollbackRef | None = None


class Confirmation(_Base):
    confirmation_id: UUID
    action_id: UUID
    trace_id: UUID
    level: Literal["critical_system", "protected_dir", "normal"]
    timeout_sec: int = Field(default=30, ge=1)
    decision: Literal["pending", "approved", "rejected", "timeout"] = "pending"
    decided_by: str | None = None
    decided_at: datetime | None = None


class Health(_Base):
    module: str
    version: str
    status: Literal["ok", "degraded", "failed", "stopped"]
    platform: Literal["windows", "linux"] | None = None
    ram_mb: float = Field(default=0.0, ge=0)
    cpu_percent: float = Field(default=0.0, ge=0)
    queue_depth: int = Field(default=0, ge=0)
    last_error: str | None = None
    capabilities: list[str] = Field(default_factory=list)


class ModuleManifest(_Base):
    name: str
    version: str
    platforms: list[Literal["windows", "linux"]] = Field(min_length=1)
    requires_capabilities: list[str] = Field(default_factory=list)
    schemas: list[str] = Field(min_length=1)
    min_core_version: str

    @field_validator("version", "min_core_version")
    @classmethod
    def _semver(cls, v: str) -> str:
        if not _SEMVER_RE.fullmatch(v):
            raise ValueError(f"not semver: {v!r}")
        return v

    @field_validator("schemas")
    @classmethod
    def _schemas(cls, v: list[str]) -> list[str]:
        for item in v:
            parse_schema_version(item)
        return v


class PlatformCapabilities(_Base):
    platform: Literal["windows", "linux"]
    os_version: str
    kernel: str | None = None
    has_etw: bool = False
    has_sysmon: bool = False
    has_wfp: bool = False
    has_auditd: bool = False
    has_ebpf: bool = False
    has_btf: bool = False
    has_bpf_lsm: bool = False
    has_fanotify: bool = False
    has_cgroup_v2: bool = False
    secure_boot: bool = False
    selinux: str | None = None
    apparmor: str | None = None


class CaseMemoryEntry(_Base):
    case_id: UUID
    created_at: datetime
    confirmed_by: Literal["rule", "analyst", "sandbox", "ensemble", "intel"]
    features: dict[str, float]
    verdict: Verdict
    context: dict[str, Any] = Field(default_factory=dict)
    platform: Literal["windows", "linux"]
    signature: str | None = None


class ModelPack(_Base):
    model_id: str
    version: str
    platform: Literal["windows", "linux"]
    format: Literal["onnx", "gguf"]
    sha256: str
    dataset_hash: str
    metrics: dict[str, float] = Field(default_factory=dict)
    limits: dict[str, Any] = Field(default_factory=dict)
    signature: str = Field(min_length=1)

    @field_validator("sha256", "dataset_hash")
    @classmethod
    def _hash(cls, v: str) -> str:
        if not _SHA256_RE.fullmatch(v.lower()):
            raise ValueError("must be a 64-char sha256 hex digest")
        return v.lower()


class QAPair(_Base):
    question: str
    answer: str
    source: str
    tags: list[str] = Field(default_factory=list)


class TaskSolution(_Base):
    task: str
    solution: str
    used_as: Literal["fewshot", "training"] = "fewshot"


class LearningUpdate(_Base):
    update_id: UUID
    version: str
    rules: list[str] | None = None
    model_packs: list[ModelPack] | None = None
    qa_pairs: list[QAPair] | None = None
    task_solutions: list[TaskSolution] | None = None
    kb_version: str | None = None
    signature: str = Field(min_length=1)


MODELS: dict[str, type[BaseModel]] = {
    "Event": Event,
    "Actor": Actor,
    "ObjectRef": ObjectRef,
    "UserRef": UserRef,
    "HostInfo": HostInfo,
    "IntegrityInfo": IntegrityInfo,
    "PiiFlags": PiiFlags,
    "KernelMeta": KernelMeta,
    "Verdict": Verdict,
    "Action": Action,
    "RollbackRef": RollbackRef,
    "Confirmation": Confirmation,
    "Health": Health,
    "ModuleManifest": ModuleManifest,
    "PlatformCapabilities": PlatformCapabilities,
    "CaseMemoryEntry": CaseMemoryEntry,
    "ModelPack": ModelPack,
    "QAPair": QAPair,
    "TaskSolution": TaskSolution,
    "LearningUpdate": LearningUpdate,
}


def validate_event(payload: dict) -> Event:
    """Validate an event payload, mapping version errors to `incompatible_schema`."""
    return Event.model_validate(payload)


class _Registry(_Base):
    models: dict[str, str]


def export_json_schemas(directory: str) -> list[str]:
    """Write one JSON Schema per model plus an index; returns written paths."""
    os.makedirs(directory, exist_ok=True)
    written: list[str] = []
    index: dict[str, str] = {}
    for name, model in MODELS.items():
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        path = os.path.join(directory, f"{name}.schema.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(schema, fh, indent=2, ensure_ascii=False)
        written.append(path)
        fname = os.path.basename(path)
        index[name] = fname
    index_path = os.path.join(directory, "index.json")
    with open(index_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema_version": SCHEMA_VERSION, "files": index}, fh, indent=2, ensure_ascii=False)
    written.append(index_path)
    return written
