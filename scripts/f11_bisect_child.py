"""One bisection block: run the soak loop with one component disabled.

MODE=full        — everything as in the soak
MODE=no_audit    — audit log appends are a no-op (isolates hashlib/fsync chain)
MODE=no_validate — pre-validated payloads are submitted directly (isolates pydantic)
MODE=no_rss      — RSS sampling skipped (isolates psutil/ctypes)

A native crash kills this process; the parent runner records the exit code.
"""

from __future__ import annotations

import os
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
from schemas.v3 import Event  # noqa: E402

MODE = os.environ.get("MODE", "full")
DURATION = float(os.environ.get("DURATION_S", "180"))
RATE = float(os.environ.get("RATE", "200"))
HOST = HostContext(host_id="bisect", os="windows", version="10", arch="x64")


def payload() -> dict:
    return {
        "schema_version": "3.0", "event_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()),
        "ts_event": datetime.now(timezone.utc).isoformat(),
        "ts_ingest": datetime.now(timezone.utc).isoformat(),
        "raw_ref": "raw/b",
        "platform": "windows", "source": "win.eventlog", "layer": "user",
        "category": "file.write", "action": "write",
        "actor": {"pid": 1, "ppid": 0, "name": "a", "path": "a",
                  "cmdline_hash": "ab" * 32, "cmdline_redacted": "a"},
        "object": {"type": "file", "path": "x"},
        "host": {"host_id": "bisect", "os": "windows", "version": "10", "arch": "x64"},
    }


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="aidf_bisect_")
    cfg = DaemonConfig(sources=["win.eventlog"],
                       thresholds={"heartbeat_timeout_s": 60}, queue={"capacity": 10000})
    d = Daemon(os.path.join(tmp, "daemon"), config=cfg, host=HOST,
               serve_http=False, log_fsync_every=64)
    if MODE == "no_audit":
        d.log.append = lambda *a, **k: None          # type: ignore[method-assign]
    if MODE == "no_rules":
        d.pipeline.engine.evaluate = lambda ev: []   # type: ignore[method-assign]

    prevalidated: Event | None = None
    if MODE == "no_validate":
        prevalidated = Event.model_validate(payload())

    d.start()
    stop = threading.Event()
    fed = [0]
    errors: list[str] = []

    def feeder() -> None:
        while not stop.is_set():
            start = time.perf_counter()
            try:
                if prevalidated is not None:
                    data = prevalidated.model_dump(mode="json")
                    d.pipeline.ingest.submit(category=data["category"], key="k",
                                             payload=data, priority=1)
                else:
                    d.submit("win.eventlog", payload())
                fed[0] += 1
                d.tick()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}")
                return
            sleep_for = max(0.0, (1.0 / RATE) - (time.perf_counter() - start))
            time.sleep(sleep_for)

    thread = threading.Thread(target=feeder, daemon=True)
    thread.start()
    deadline = time.time() + DURATION
    while time.time() < deadline:
        time.sleep(1.0)
    stop.set()
    thread.join(timeout=5)
    health = d.health()
    d.stop()
    print(f"OK mode={MODE} fed={fed[0]} lost={health['ingest']['lost']} "
          f"errors={errors[:2]}")


if __name__ == "__main__":
    main()
