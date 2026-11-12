"""Shared fixtures: build valid Event v3.0 objects for tests."""

from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone

import pytest

from schemas.v3 import Event

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)


def _merge(base: dict, overrides: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


@pytest.fixture
def make_event():
    """Factory: make_event(category=..., actor={"path": ...}, platform_data={...})."""

    def _make(category: str = "process.start", action: str = "start", **overrides) -> Event:
        payload = {
            "schema_version": "3.0",
            "event_id": str(uuid.uuid4()),
            "trace_id": str(uuid.uuid4()),
            "ts_event": NOW.isoformat(),
            "ts_ingest": NOW.isoformat(),
            "platform": "windows",
            "source": "win.etw.ti",
            "layer": "kernel",
            "category": category,
            "action": action,
            "actor": {
                "pid": 4242,
                "ppid": 1000,
                "name": "notepad.exe",
                "path": r"C:\Windows\System32\notepad.exe",
                "cmdline_hash": "ab" * 32,
                "cmdline_redacted": "notepad.exe",
            },
            "object": {"type": "file", "path": r"C:\Users\public\doc.txt"},
            "host": {"host_id": "host-1", "os": "windows", "version": "10.0.19045",
                     "arch": "x64"},
            "raw_ref": "raw/x.jsonl.zst#1",
            "platform_data": {},
        }
        return Event.model_validate(_merge(payload, overrides))

    return _make
