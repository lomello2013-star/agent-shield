"""Chaos run for the `aidfd` skeleton: source death, bad config, log tamper, clock jump,
event storm, health endpoint. Writes artifacts/chaos_report.json.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.daemon import Daemon, DaemonConfig
from core.normalize import HostContext

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "artifacts", "chaos_report.json")
HOST = HostContext(host_id="host-chaos", os="windows", version="10.0.19045", arch="x64")


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def etw(i=0, lsass=False):
    return {"process_id": 500 + i, "parent_id": 4,
            "process_name": r"C:\Temp\dropper.exe" if lsass else r"C:\Windows\System32\cmd.exe",
            "target": r"C:\Windows\System32\lsass.exe" if lsass else r"C:\Users\f.txt",
            "category": "process.access" if lsass else "file.write",
            "action": "open_process" if lsass else "write"}


def make_daemon(tmp, serve_http=True, timeout_s=1.0):
    cfg = DaemonConfig(sources=["win.etw.ti"],
                       thresholds={"heartbeat_timeout_s": timeout_s, "alert_budget": 5,
                                   "min_confidence": 0.5},
                       queue={"capacity": 2000})
    return Daemon(os.path.join(tmp, "daemon"), config=cfg, host=HOST, serve_http=serve_http)


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="aidf_chaos_")
    d = make_daemon(tmp)
    d.start()
    report: dict = {"environment": {"python": sys.version.split()[0]}}

    # 1. baseline: throughput and health latency
    t0 = time.perf_counter()
    for i in range(2000):
        d.submit("win.etw.ti", etw(i, lsass=(i % 200 == 0)))
    submit_s = time.perf_counter() - t0
    tick_lat = []
    for _ in range(10):
        t = time.perf_counter()
        d.tick()
        tick_lat.append((time.perf_counter() - t) * 1000)
    health_lat = []
    for _ in range(30):
        t = time.perf_counter()
        with urllib.request.urlopen(f"http://127.0.0.1:{d.port}/health", timeout=5) as r:
            r.read()
        health_lat.append((time.perf_counter() - t) * 1000)
    health = d.health()
    report["baseline"] = {
        "submitted": 2000, "submit_s": round(submit_s, 3),
        "tick_ms_p50": round(statistics.median(tick_lat), 3), "tick_ms_p95": p95(tick_lat),
        "health_http_ms_p50": round(statistics.median(health_lat), 3),
        "health_http_ms_p95": p95(health_lat),
        "verdicts": health["verdicts"], "containments": health["containments"],
        "alerts": health["alerts"], "lost": health["ingest"]["lost"],
        "ledger_ok": health["ledger_ok"],
    }

    # 2. silent source death -> detection latency (R2 proxy).
    # Start the clock at a fresh heartbeat, so latency is measured from the last
    # beat, not from whenever the previous phase happened to finish.
    d.heartbeat.timeout_s = 0.2
    d.submit("win.etw.ti", etw(0))
    d.tick()
    t0 = time.perf_counter()
    detected = None
    while time.perf_counter() - t0 < 5:
        d.tick()
        if d.health()["status"] == "degraded":
            detected = time.perf_counter() - t0
            break
        time.sleep(0.01)
    report["source_death"] = {"detection_s": round(detected, 3) if detected else None,
                              "timeout_s": 0.2, "detected": detected is not None,
                              "status_after": d.health()["status"],
                              "note": "measured from the last heartbeat; worst case = "
                                      "timeout + tick period"}

    # 3. bad config -> safe mode, LKG preserved
    from core.daemon import DaemonConfig as Cfg
    good = d.safe_mode.load_lkg()
    bad = Cfg(thresholds={"alert_budget": -1}).as_payload()
    res = d.safe_mode.apply(bad, dry_run=False)
    report["bad_config"] = {"accepted": res.accepted, "safe_mode": d.safe_mode.is_safe,
                            "lkg_unchanged": d.safe_mode.load_lkg() == good,
                            "status": d.health()["status"]}

    # 4. audit log tamper -> health detects
    with open(d.log.path, "a", encoding="utf-8") as fh:
        fh.write('{"forged": true}\n')
    t0 = time.perf_counter()
    h = d.health()
    report["audit_tamper"] = {"detected": h["audit_chain_ok"] is False,
                              "detect_ms": round((time.perf_counter() - t0) * 1000, 3),
                              "status": h["status"]}

    # 5. clock jump -> logged as incident
    class FakeWall:
        def __init__(self):
            self.t = time.time()
        def __call__(self):
            return self.t
    fake = FakeWall()
    d.clock._wall_fn = fake
    d.clock._last_wall = fake.t
    fake.t += 3600
    d.tick()
    jumps = [json.loads(line) for line in open(d.log.path, encoding="utf-8")
             if '"clock_jump"' in line]
    report["clock_jump"] = {"logged": len(jumps) > 0, "events": len(jumps)}

    # 6. event storm with no consumer -> spill, no loss, then drain
    before = d.pipeline.ingest.stats()["received"]
    for i in range(5000):
        d.submit("win.etw.ti", etw(i, lsass=(i % 100 == 0)))
    mid = d.pipeline.ingest.stats()
    while d.pipeline.ingest.backlog_events() > 0:
        d.tick()
    after = d.pipeline.ingest.stats()
    report["storm"] = {"submitted": 5000,
                       "backlog_before_drain": mid["backlog"],
                       "spilled_pending_before_drain": mid["spilled_pending"],
                       "lost": after["lost"], "ledger_ok": d.pipeline.ingest.ledger_ok(),
                       "received_total": after["received"], "delivered": after["delivered"]}

    # 7. graceful shutdown
    t0 = time.perf_counter()
    d.stop()
    report["shutdown_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    report["final"] = {"lost_total": after["lost"], "quarantined_records":
                       d.pipeline.normalizer.stats()["quarantined"]}

    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
