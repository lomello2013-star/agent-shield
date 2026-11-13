"""Tests for the newly wired product path: collectors and response execution."""

from __future__ import annotations

import sys

import pytest

from core.daemon import Daemon, DaemonConfig
from core.normalize import HostContext
from core.response import ConfirmationManager, ExecutionResult, ResponseExecutor

HOST = HostContext(host_id="h", os="windows", version="10", arch="x64")


def make_daemon(tmp_path, **kwargs):
    cfg = DaemonConfig(sources=["win.eventlog"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 10,
                                   "min_confidence": 0.5},
                       queue={"capacity": 1000})
    return Daemon(str(tmp_path / "daemon"), config=cfg, host=HOST, **kwargs)


class FakeCollector:
    """Yields the same 7045 service-install record (a real rule trigger)."""

    name = "win.eventlog"

    def __init__(self, records: int = 1):
        self.records = records

    def poll(self):
        return [{
            "category": "persistence.change", "action": "service_create",
            "path": r"C:\Temp\evil.exe", "event_id": 7045,
            "provider": "Service Control Manager", "record_id": index + 1,
            "ts": "2026-11-13T20:00:00Z",
            "data": {"ServiceName": "EvilSvc", "ImagePath": r"C:\Temp\evil.exe",
                     "ServiceType": "user mode service", "StartType": "auto start"},
        } for index in range(self.records)]


def test_collectors_are_polled_and_records_processed(tmp_path):
    collector = FakeCollector(records=2)
    d = make_daemon(tmp_path, collectors=[collector])
    assert d.collect_once() == 2
    assert d.collected_count == 2
    result = d.tick()
    assert result["verdicts"] >= 1, "a service-install record must trigger WIN-SERVICE-CREATE-007"
    d.stop()


def test_collector_loop_starts_and_stops_cleanly(tmp_path):
    d = make_daemon(tmp_path, collectors=[FakeCollector(records=1)], collect_interval_s=0.01)
    d.start()
    for _ in range(50):
        if d.collected_count > 0:
            break
        import time
        time.sleep(0.02)
    d.stop()
    assert d.collected_count > 0, "background collector thread did not poll"
    assert d._collector_thread is None


class FakeResponse:
    def __init__(self, status: str = "refused"):
        self.status = status
        self.calls = []
        self.quarantine = None

    def execute(self, action):
        self.calls.append(action)
        return ExecutionResult(action, self.status, "confirmation_required")


def test_gate_actions_reach_the_response_layer(tmp_path):
    fake = FakeResponse()
    collector = FakeCollector(records=1)
    d = make_daemon(tmp_path, response=fake, collectors=[collector])
    assert d.collect_once() == 1
    d.tick()
    assert fake.calls, "response layer was not called for a gate action"
    assert d.response_refused >= 1
    d.stop()


def test_response_errors_do_not_break_detection(tmp_path):
    class Boom(FakeResponse):
        def execute(self, action):
            raise RuntimeError("boom")

    d = make_daemon(tmp_path, response=Boom(), collectors=[FakeCollector(records=1)])
    assert d.collect_once() == 1
    d.tick()                          # must not raise
    assert d.response_failed >= 1
    assert "boom" in d.last_response_error
    d.stop()


@pytest.mark.skipif(sys.platform != "win32", reason="wevtutil is Windows-only")
def test_real_eventlog_collector_is_built(tmp_path):
    """P0: the daemon must build the real (non-admin) event-log collector."""
    cfg = DaemonConfig(sources=["win.eventlog"])
    d = Daemon(str(tmp_path / "d"), config=cfg, host=HOST)
    assert "win.eventlog" in [getattr(c, "name", "") for c in d.collectors]
    d.stop()


@pytest.mark.skipif(sys.platform != "win32", reason="wevtutil is Windows-only")
def test_real_eventlog_collector_polls(tmp_path):
    """The real collector is actually polled (may return 0 new records)."""
    cfg = DaemonConfig(sources=["win.eventlog"])
    d = Daemon(str(tmp_path / "d"), config=cfg, host=HOST)
    submitted = d.collect_once()      # must not raise; 0 is a valid result
    assert submitted >= 0
    d.stop()
