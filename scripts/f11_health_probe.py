"""Reproduce the ~20-minute soak hang in a focused experiment.

Hypothesis: `Daemon.health()` calls `HashChainLog.verify(incremental=True)`, whose read
loop re-scans the log while the writer appends faster than the reader advances, so the
call never returns. This script hammers health() while events are appended and measures
the latency distribution; a growing tail is the reproduction.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

OUT = os.path.join(HERE, "artifacts", "f11_health_livelock.json")
HOST = HostContext(host_id="h", os="windows", version="10", arch="x64")


def event() -> dict:
    return {
        "schema_version": "3.0", "event_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()),
        "ts_event": datetime.now(timezone.utc).isoformat(),
        "ts_ingest": datetime.now(timezone.utc).isoformat(),
        "raw_ref": "raw/x",
        "category": "file.write", "action": "write",
        "actor": {"pid": 1, "ppid": 0, "name": "a", "path": "a",
                  "cmdline_hash": "ab" * 32, "cmdline_redacted": "a"},
        "object": {"type": "file", "path": "x"},
        "host": {"host_id": "h", "os": "windows", "version": "10", "arch": "x64"},
    }


def main() -> None:
    duration = float(os.environ.get("AIDF_DEBUG_SECONDS", "120"))
    rate = float(os.environ.get("AIDF_DEBUG_RATE", "200"))
    root = tempfile.mkdtemp(prefix="aidf_livelock_")
    cfg = DaemonConfig(sources=["win.eventlog"], thresholds={"heartbeat_timeout_s": 60},
                       queue={"capacity": 10000})
    d = Daemon(root, config=cfg, host=HOST, log_fsync_every=1)
    d.start()
    stop = threading.Event()
    fed = [0]
    latencies: list[float] = []
    errors: list[str] = []

    def feeder() -> None:
        payload = event()
        while not stop.is_set():
            start = time.perf_counter()
            try:
                d.submit("win.eventlog", payload)
                d.tick()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"feeder: {type(exc).__name__}: {exc}")
                return
            fed[0] += 1
            sleep_for = max(0.0, (1.0 / rate) - (time.perf_counter() - start))
            time.sleep(sleep_for)

    def sampler() -> None:
        while not stop.is_set():
            t0 = time.perf_counter()
            try:
                d.health()
                latencies.append((time.perf_counter() - t0) * 1000)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"health: {type(exc).__name__}: {exc}")
                latencies.append(float("inf"))
                return
            time.sleep(0.5)

    threads = [threading.Thread(target=feeder, daemon=True),
               threading.Thread(target=sampler, daemon=True)]
    for thread in threads:
        thread.start()
    deadline = time.time() + duration
    while time.time() < deadline:
        time.sleep(1.0)
        if latencies and latencies[-1] > 5000:
            break
    stop.set()
    time.sleep(0.5)
    health = d.health()
    d.stop()

    finite = [value for value in latencies if value != float("inf")]
    report = {
        "seconds": duration, "rate": rate, "events_fed": fed[0],
        "health_calls": len(latencies),
        "health_ms_p50": round(statistics.median(finite), 2) if finite else None,
        "health_ms_max": round(max(finite), 2) if finite else None,
        "health_ms_last": round(finite[-1], 2) if finite else None,
        "stalled": bool(latencies) and latencies[-1] == float("inf"),
        "errors": errors[:5],
        "lost": health["ingest"]["lost"],
        "log_records": None,
        "note": "growing health latency / stall reproduces the soak hang; the caller is "
                "Daemon.health -> HashChainLog.verify(incremental=True)",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
