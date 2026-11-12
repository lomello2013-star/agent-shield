import json
import os
import time
import urllib.request

import pytest

from core.daemon import Daemon, DaemonConfig
from core.normalize import HostContext

HOST = HostContext(host_id="host-test", os="windows", version="10.0.19045", arch="x64")


def etw(lsass=False):
    return {"process_id": 500, "parent_id": 4,
            "process_name": r"C:\Temp\dropper.exe", "cmdline": "drop",
            "target": (r"C:\Windows\System32\lsass.exe" if lsass else r"C:\Users\f.txt"),
            "category": "process.access" if lsass else "file.write",
            "action": "open_process" if lsass else "write"}


def make_daemon(tmp_path, **kwargs):
    cfg = DaemonConfig(sources=["win.etw.ti"], thresholds={"heartbeat_timeout_s": 1.0,
                                                           "alert_budget": 10,
                                                           "min_confidence": 0.5},
                       queue={"capacity": 1000})
    return Daemon(str(tmp_path / "daemon"), config=cfg, host=HOST, **kwargs)


def test_daemon_starts_healthy_and_applies_config(tmp_path):
    d = make_daemon(tmp_path)
    health = d.health()
    assert health["status"] == "ok"
    assert health["ledger_ok"] and health["audit_chain_ok"] and health["integrity_ok"]
    assert d.safe_mode.load_lkg()["schema_version"] == "1.0"
    d.stop()


def test_daemon_processes_events_to_verdict(tmp_path):
    d = make_daemon(tmp_path)
    assert d.submit("win.etw.ti", etw(lsass=True)) is True
    result = d.tick()
    assert result["verdicts"] == 1
    health = d.health()
    assert health["verdicts"] == 1 and health["containments"] == 1
    d.stop()


def test_daemon_detects_silent_source(tmp_path):
    d = make_daemon(tmp_path)
    d.submit("win.etw.ti", etw())
    d.tick()
    # no beats for longer than the (compressed) 1 s contract; F04 derives the early
    # thresholds from the contract, so they must be compressed too
    d.heartbeat.timeout_s = 0.05
    d.heartbeat.warn_s = 0.02
    d.heartbeat.escalate_s = 0.04
    time.sleep(0.1)
    result = d.tick()
    assert result["incidents"] == 1
    assert d.health()["status"] == "degraded"
    d.stop()


def test_bad_config_enters_safe_mode_and_keeps_lkg(tmp_path):
    d = make_daemon(tmp_path)
    good_lkg = d.safe_mode.load_lkg()
    bad = DaemonConfig(schema_version="1.0", sources=["win.etw.ti"],
                       thresholds={"alert_budget": -5})     # negative threshold
    result = d.safe_mode.apply(bad.as_payload(), dry_run=False)
    assert result.accepted is False
    assert d.safe_mode.is_safe is True
    assert d.safe_mode.load_lkg() == good_lkg
    d.stop()


def test_health_reports_tampered_audit_chain(tmp_path):
    d = make_daemon(tmp_path)
    d.submit("win.etw.ti", etw())
    d.tick()
    path = d.log.path
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("{broken}\n")
    health = d.health()
    assert health["audit_chain_ok"] is False
    assert health["status"] == "degraded"
    d.stop()


def test_self_test_reports_all_checks(tmp_path):
    d = make_daemon(tmp_path)
    report = d.run_self_test()
    assert report["ok"] is True
    names = [c["check"] for c in report["checks"]]
    assert names == ["immutable_policy", "audit_chain", "file_integrity"]
    d.stop()


def test_http_health_endpoint(tmp_path):
    d = make_daemon(tmp_path, serve_http=True)
    d.start()
    try:
        assert d.port > 0
        with urllib.request.urlopen(f"http://127.0.0.1:{d.port}/health", timeout=5) as resp:
            payload = json.loads(resp.read())
        assert payload["status"] == "ok"
        with urllib.request.urlopen(f"http://127.0.0.1:{d.port}/stats", timeout=5) as resp:
            stats = json.loads(resp.read())
        assert "pipeline" in stats
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(f"http://127.0.0.1:{d.port}/nope", timeout=5)
    finally:
        d.stop()


def test_run_for_processes_until_deadline(tmp_path):
    d = make_daemon(tmp_path)
    d.submit("win.etw.ti", etw(lsass=True))
    t0 = time.monotonic()
    d.run_for(0.2, interval_s=0.02)
    elapsed = time.monotonic() - t0
    assert 0.15 <= elapsed < 2.0
    assert d.verdict_count == 1
    d.stop()


def test_stop_is_idempotent_and_seals_chain(tmp_path):
    d = make_daemon(tmp_path)
    d.submit("win.etw.ti", etw())
    d.tick()
    d.stop()
    d.stop()
    assert os.path.exists(d.log.anchor_path)


def test_health_does_not_rehash_manifest_on_every_call(tmp_path):
    """F11: health() is called every 2 s; the manifest must be cached between calls."""
    d = make_daemon(tmp_path)
    calls = {"n": 0}
    real_verify = d.manifest.verify

    def counting():
        calls["n"] += 1
        return real_verify()

    d.manifest.verify = counting
    for _ in range(5):
        d.health()
    assert calls["n"] == 1, "manifest re-hashed on every health() call"

    d._integrity_checked_at -= d.config.manifest_interval_s + 1
    d.health()
    assert calls["n"] == 2, "manifest must be re-verified after the interval"
    d.stop()
