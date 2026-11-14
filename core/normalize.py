"""Telemetry normalization: raw source records -> Event v3.0 (stage 4).

Rules:
  * a normalizer never guesses silently: unknown source or missing required field
    raises ``NormalizationError`` with a reason;
  * a rejected record is **quarantined** (written to disk with the reason), never
    dropped silently вЂ” R8 applies to parsing as well;
  * timestamps: ``ts_event`` comes from the source when present, ``ts_ingest`` is
    our own clock; a bad source timestamp falls back to ingest time and is
    counted, not hidden;
  * PII: cmdline is redacted/truncated, paths stay (needed for rules), IPs flagged.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from core.counters import LossCounters
from schemas.v3 import Event

MAX_CMDLINE = 200


class NormalizationError(ValueError):
    """Raw record cannot be turned into a valid Event."""

    def __init__(self, reason: str, field_name: str = "") -> None:
        super().__init__(f"{reason}" + (f" (field={field_name})" if field_name else ""))
        self.reason = reason
        self.field_name = field_name


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def _hash_cmdline(cmdline: str) -> str:
    return hashlib.sha256(cmdline.encode("utf-8", "replace")).hexdigest()


def _parse_ts(value: Any, fallback: datetime) -> tuple[datetime, bool]:
    if value is None:
        # No source timestamp is normal (many providers omit it): use ingest time.
        return fallback, True
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc), True
        except (OverflowError, OSError, ValueError):
            return fallback, False
    if isinstance(value, str):
        try:
            text = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt, True
        except ValueError:
            return fallback, False
    return fallback, False


@dataclass(frozen=True)
class HostContext:
    host_id: str
    os: str
    version: str
    arch: str
    kernel: str | None = None

    def as_payload(self) -> dict[str, str]:
        payload = {"host_id": self.host_id, "os": self.os, "version": self.version,
                   "arch": self.arch}
        if self.kernel:
            payload["kernel"] = self.kernel
        return payload


@dataclass
class Adapter:
    """Declarative mapping for one telemetry source."""

    source: str
    platform: str
    layer: str
    build: Callable[[dict, datetime], dict]


def _req(raw: dict, name: str) -> Any:
    if name not in raw or raw[name] in (None, ""):
        raise NormalizationError("missing required field", name)
    return raw[name]


# --------------------------------------------------------------------- adapters
def _etw_ti(raw: dict, now: datetime) -> dict:
    image = str(_req(raw, "process_name"))
    cmdline = str(raw.get("cmdline") or "")
    actor = {
        "pid": int(_req(raw, "process_id")),
        "ppid": int(raw["parent_id"]) if raw.get("parent_id") is not None else None,
        "name": _basename(image),
        "path": image,
        "cmdline_hash": _hash_cmdline(cmdline),
        "cmdline_redacted": cmdline[:MAX_CMDLINE],
        "sha256": raw.get("image_sha256"),
        "signature": raw.get("signature"),
    }
    target = raw.get("target")
    obj = None
    if target:
        obj = {"type": str(raw.get("target_type") or "process"), "path": str(target),
               "sha256": raw.get("target_sha256")}
    return {
        "category": str(raw.get("category") or "process.access"),
        "action": str(raw.get("action") or "open_process"),
        "actor": actor,
        "object": obj,
        "platform_data": {k: v for k, v in raw.items()
                          if k in ("event_id", "keyword", "level", "parent_name")},
    }


def _linux_ebpf(raw: dict, now: datetime) -> dict:
    pid = int(_req(raw, "pid"))
    comm = str(raw.get("comm") or "")
    exe = raw.get("exe") or comm
    syscall = str(raw.get("syscall") or "")
    category = str(raw.get("category") or "")
    if not category:
        category = {
            "execve": "process.start", "execveat": "process.start",
            "openat": "file.write", "open": "file.write", "write": "file.write",
            "unlink": "file.delete", "unlinkat": "file.delete",
            "connect": "net.connect", "accept": "net.listen",
        }.get(syscall)
        if not category:
            raise NormalizationError("unmapped syscall", "syscall")
    filename = raw.get("filename")
    if category == "net.connect" and raw.get("dport") is not None:
        daddr = str(raw.get("daddr") or "")
        dport = int(raw["dport"])
        obj = {"type": "network", "path": f"{daddr}:{dport}", "ip": daddr,
               "port": dport, "proto": str(raw.get("proto") or "tcp")}
    elif filename:
        obj = {"type": "file", "path": str(filename)}
    else:
        obj = None
    return {
        "category": category,
        "action": str(raw.get("action") or syscall or "event"),
        "actor": {
            "pid": pid,
            "ppid": int(raw["ppid"]) if raw.get("ppid") is not None else None,
            "name": comm or _basename(str(exe)),
            "path": str(exe),
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
            "uid": str(raw["uid"]) if raw.get("uid") is not None else None,
            "container_id": raw.get("container_id"),
        },
        "object": obj,
        "platform_data": {k: v for k, v in raw.items()
                          if k in ("syscall", "cgroup", "ret", "comm",
                                   "daddr", "dport", "proto")},
    }


def _win_amsi(raw: dict, now: datetime) -> dict:
    app = str(_req(raw, "app_name"))
    content = str(_req(raw, "content_name"))
    return {
        "category": "script.execute",
        "action": "amsi_scan",
        "actor": {
            "pid": int(raw["process_id"]) if raw.get("process_id") is not None else None,
            "name": _basename(app),
            "path": app,
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
        } if raw.get("process_id") is not None else None,
        "object": {"type": "script", "path": content},
        "platform_data": {"amsi_result": raw.get("result"),
                          "session": raw.get("session")},
    }


def _linux_auditd(raw: dict, now: datetime) -> dict:
    exe = str(_req(raw, "exe"))
    key = str(raw.get("key") or "")
    category = {
        "exec": "process.start", "execve": "process.start",
        "connect": "net.connect", "open": "file.write",
        "delete": "file.delete", "persistence": "persistence.change",
    }.get(key)
    if not category:
        raise NormalizationError("unmapped auditd key", "key")
    return {
        "category": category,
        "action": key,
        "actor": {
            "pid": int(_req(raw, "pid")),
            "ppid": int(raw["ppid"]) if raw.get("ppid") is not None else None,
            "name": _basename(exe),
            "path": exe,
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
            "uid": str(raw["uid"]) if raw.get("uid") is not None else None,
        },
        "object": {"type": "file", "path": str(raw["path"])} if raw.get("path") else None,
        "platform_data": {"audit_key": key, "audit_type": raw.get("type")},
    }


def _linux_lsm(raw: dict, now: datetime) -> dict:
    pid = int(_req(raw, "pid"))
    comm = str(raw.get("comm") or "")
    path = str(_req(raw, "path"))
    exe = str(raw.get("exe") or "")
    return {
        "category": str(raw.get("category") or "file.read"),
        "action": str(raw.get("action") or "open"),
        "actor": {
            "pid": pid,
            "ppid": int(raw["ppid"]) if raw.get("ppid") is not None else None,
            "name": comm or _basename(path),
            "path": exe,
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
            "uid": str(raw["uid"]) if raw.get("uid") is not None else None,
        },
        "object": {"type": "file", "path": path},
        "platform_data": {"lsm_hook": raw.get("hook", "file_open")},
    }


def _linux_net(raw: dict, now: datetime) -> dict:
    pid = int(_req(raw, "pid"))
    comm = str(raw.get("comm") or "")
    dport = int(_req(raw, "dport"))
    daddr = str(raw.get("daddr") or "")
    exe = str(raw.get("exe") or "")
    return {
        "category": "net.connect",
        "action": "connect",
        "actor": {
            "pid": pid,
            "ppid": int(raw["ppid"]) if raw.get("ppid") is not None else None,
            "name": comm or str(pid),
            "path": exe,
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
        },
        "object": {"type": "network", "path": f"{daddr}:{dport}", "ip": daddr,
                   "port": dport, "proto": str(raw.get("proto") or "tcp")},
        "platform_data": {"hook": raw.get("hook", "cgroup/connect4"),
                          "provenance_known": bool(exe)},
    }


def _win_eventlog(raw: dict, now: datetime) -> dict:
    category = str(raw.get("category") or "unknown")
    action = str(raw.get("action") or "event")
    path = str(raw.get("path") or raw.get("object_path") or "")
    if path.startswith("<"):
        path = ""                      # e.g. Sysmon "<unknown process>"
    object_path = str(raw.get("object_path") or path)
    if object_path.startswith("<"):
        object_path = ""
    if category.startswith("process."):
        obj_type = "process"
    elif category.startswith("registry."):
        obj_type = "registry"
    elif category.startswith("file."):
        obj_type = "file"
    elif category.startswith("persistence.") and "wmi" in action:
        obj_type = "wmi"
    else:
        obj_type = "service"
    obj = {"type": obj_type, "path": object_path} if object_path else None
    data = raw.get("data") or {}
    pid = raw.get("process_id")
    actor = None
    if pid is not None:
        image = str(raw.get("image") or path or "")
        cmdline = str(raw.get("cmdline") or "")
        actor = {
            "pid": int(pid),
            "ppid": int(raw["parent_id"]) if raw.get("parent_id") is not None else None,
            "name": _basename(image) or str(pid),
            "path": image,
            "cmdline_hash": _hash_cmdline(cmdline),
            "cmdline_redacted": cmdline[:MAX_CMDLINE],
        }
    return {
        "category": category,
        "action": action,
        "actor": actor,
        "object": obj,
        "platform_data": {
            "event_id": raw.get("event_id"),
            "provider": raw.get("provider"),
            "record_id": raw.get("record_id"),
            "cmdline": str(raw.get("cmdline") or ""),
            "image": str(raw.get("image") or ""),
            "parent_name": _basename(str(raw.get("parent_image") or "")),
            **{k: v for k, v in data.items() if k in ("ServiceName", "ServiceType",
                                                      "StartType", "AccountName")},
        },
    }


def _linux_memory(raw: dict, now: datetime) -> dict:
    pid = int(_req(raw, "pid"))
    target = int(_req(raw, "target"))
    comm = str(raw.get("comm") or "")
    exe = str(raw.get("exe") or "")
    return {
        "category": "memory.access",
        "action": "process_vm_writev",
        "actor": {
            "pid": pid,
            "ppid": int(raw.get("ppid") or 0),
            "name": comm or str(pid),
            "path": exe,
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
        },
        "object": {"type": "process", "path": f"pid:{target}", "port": None},
        "platform_data": {"target_pid": target, "riovcnt": raw.get("bytes"),
                          "provenance_known": bool(exe)},
    }


def _linux_ptrace(raw: dict, now: datetime) -> dict:
    pid = int(_req(raw, "pid"))
    target = int(_req(raw, "target"))
    request = int(raw.get("request") or 0)
    comm = str(raw.get("comm") or "")
    exe = str(raw.get("exe") or "")
    return {
        "category": "memory.access",
        "action": "ptrace_poke",
        "actor": {
            "pid": pid,
            "ppid": int(raw.get("ppid") or 0),
            "name": comm or str(pid),
            "path": exe,
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
        },
        "object": {"type": "process", "path": f"pid:{target}"},
        "platform_data": {"target_pid": target, "ptrace_request": request,
                          "provenance_known": bool(exe)},
    }


def _linux_procmem(raw: dict, now: datetime) -> dict:
    pid = int(_req(raw, "pid"))
    path = str(_req(raw, "path"))
    writable = bool(raw.get("writable"))
    comm = str(raw.get("comm") or "")
    exe = str(raw.get("exe") or "")
    return {
        "category": "memory.access",
        "action": "proc_mem_write" if writable else "proc_mem_read",
        "actor": {
            "pid": pid,
            "ppid": int(raw.get("ppid") or 0),
            "name": comm or str(pid),
            "path": exe,
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
        },
        "object": {"type": "process", "path": path},
        "platform_data": {"proc_path": path, "writable": writable,
                          "provenance_known": bool(exe)},
    }


def _linux_mprotect(raw: dict, now: datetime) -> dict:
    pid = int(_req(raw, "pid"))
    comm = str(raw.get("comm") or "")
    exe = str(raw.get("exe") or "")
    anon = bool(raw.get("anon"))
    return {
        "category": "memory.access",
        "action": "mprotect_exec",
        "actor": {
            "pid": pid,
            "ppid": int(raw.get("ppid") or 0),
            "name": comm or str(pid),
            "path": exe,
            "cmdline_hash": _hash_cmdline(str(raw.get("cmdline") or "")),
            "cmdline_redacted": str(raw.get("cmdline") or "")[:MAX_CMDLINE],
        },
        "object": {"type": "memory", "path": f"pid:{pid}:rwx"},
        "platform_data": {"anon": anon, "length": raw.get("len"),
                          "provenance_known": bool(exe)},
    }


ADAPTERS: dict[str, Adapter] = {
    "win.etw.ti": Adapter("win.etw.ti", "windows", "kernel", _etw_ti),
    "win.amsi": Adapter("win.amsi", "windows", "script", _win_amsi),
    "win.eventlog": Adapter("win.eventlog", "windows", "user", _win_eventlog),
    "win.defender": Adapter("win.defender", "windows", "user", _win_eventlog),
    "win.sysmon": Adapter("win.sysmon", "windows", "user", _win_eventlog),
    "win.security": Adapter("win.security", "windows", "user", _win_eventlog),
    "linux.ebpf": Adapter("linux.ebpf", "linux", "kernel", _linux_ebpf),
    "linux.auditd": Adapter("linux.auditd", "linux", "kernel", _linux_auditd),
    "linux.lsm": Adapter("linux.lsm", "linux", "kernel", _linux_lsm),
    "linux.net": Adapter("linux.net", "linux", "network", _linux_net),
    "linux.memory": Adapter("linux.memory", "linux", "memory", _linux_memory),
    "linux.ptrace": Adapter("linux.ptrace", "linux", "memory", _linux_ptrace),
    "linux.procmem": Adapter("linux.procmem", "linux", "memory", _linux_procmem),
    "linux.mprotect": Adapter("linux.mprotect", "linux", "memory", _linux_mprotect),
}


@dataclass
class Normalizer:
    host: HostContext
    quarantine_path: str | None = None
    counters: LossCounters = field(default_factory=LossCounters)
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    _quarantined: int = 0
    _bad_timestamps: int = 0

    def normalize(self, source: str, raw: dict) -> Event:
        adapter = ADAPTERS.get(source)
        if adapter is None:
            raise NormalizationError(f"unknown source: {source}", "source")
        if not isinstance(raw, dict):
            raise NormalizationError("raw record must be an object", "raw")
        now = self.now_fn()
        ts_event, ok = _parse_ts(raw.get("ts"), now)
        if not ok:
            self._bad_timestamps += 1
            self.counters.inc("bad_timestamp")
        try:
            body = adapter.build(raw, now)
        except NormalizationError:
            raise
        except (TypeError, ValueError) as exc:
            raise NormalizationError(f"bad value: {exc}") from exc
        payload = {
            "schema_version": "3.0",
            "event_id": str(uuid.uuid4()),
            "trace_id": str(raw.get("trace_id") or uuid.uuid4()),
            "ts_event": ts_event.isoformat(),
            "ts_ingest": now.isoformat(),
            "platform": adapter.platform,
            "source": adapter.source,
            "layer": adapter.layer,
            "host": self.host.as_payload(),
            "raw_ref": str(raw.get("raw_ref") or f"raw/{source}/{uuid.uuid4()}.json"),
            "pii": {"paths_hashed": False, "cmdline_hashed": True,
                    "usernames_hashed": True, "ips_hashed": False},
        }
        payload.update(body)
        try:
            return Event.model_validate(payload)
        except Exception as exc:            # pydantic ValidationError
            raise NormalizationError(f"schema validation failed: {exc}") from exc

    def normalize_or_quarantine(self, source: str, raw: dict) -> Event | None:
        try:
            return self.normalize(source, raw)
        except NormalizationError as exc:
            self.quarantine(source, raw, exc.reason)
            return None

    def quarantine(self, source: str, raw: dict, reason: str) -> None:
        self._quarantined += 1
        self.counters.inc("quarantined")
        if not self.quarantine_path:
            return
        try:
            os.makedirs(os.path.dirname(self.quarantine_path) or ".", exist_ok=True)
            line = json.dumps({"ts": self.now_fn().isoformat(), "source": source,
                               "reason": reason, "raw": raw}, ensure_ascii=False, default=str)
            with open(self.quarantine_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            self.counters.inc("quarantine_write_failed")

    def stats(self) -> dict[str, int]:
        return {"quarantined": self._quarantined,
                "bad_timestamps": self._bad_timestamps}

