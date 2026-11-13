"""Child process for the supervisor measurement: a real daemon that appends to audit.

Env: AIDF_CHILD_ROOT (daemon data dir), AIDF_CHILD_RATE (events/s), AIDF_CHILD_READY_FILE
Prints `READY` once the daemon is up, then feeds events until terminated.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

ROOT = os.environ["AIDF_CHILD_ROOT"]
RATE = float(os.environ.get("AIDF_CHILD_RATE", "50"))
READY = os.environ.get("AIDF_CHILD_READY_FILE", "")
HOST = HostContext(host_id="sup", os="windows", version="10", arch="x64")


def payload() -> dict:
    return {
        "schema_version": "3.0", "event_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()),
        "ts_event": datetime.now(timezone.utc).isoformat(),
        "ts_ingest": datetime.now(timezone.utc).isoformat(),
        "raw_ref": "raw/sup",
        "platform": "windows", "source": "win.eventlog", "layer": "user",
        "category": "file.write", "action": "write",
        "actor": {"pid": 1, "ppid": 0, "name": "a", "path": "a",
                  "cmdline_hash": "ab" * 32, "cmdline_redacted": "a"},
        "object": {"type": "file", "path": "x"},
        "host": {"host_id": "sup", "os": "windows", "version": "10", "arch": "x64"},
    }


def main() -> None:
    cfg = DaemonConfig(sources=["win.eventlog"], thresholds={"heartbeat_timeout_s": 60},
                       queue={"capacity": 5000})
    d = Daemon(ROOT, config=cfg, host=HOST, serve_http=False, log_fsync_every=8)
    d.start()
    if READY:
        with open(READY, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))
    last_beat = 0.0
    last_health = 0.0
    health_sampling = os.environ.get("AIDF_CHILD_HEALTH") == "1"
    try:
        while True:
            d.submit("win.eventlog", payload())
            d.tick()
            now = time.monotonic()
            if health_sampling and now - last_health >= 2.0:
                # same cadence as the soak: health() verifies the audit chain
                d.health()
                last_health = now
            if now - last_beat >= 1.0:
                # one audit record per second: lets the supervisor measurement verify
                # that the hash chain continues across restarts
                d.log.append("child_beat", {"pid": os.getpid()})
                d.log.flush()          # fsync_every>1 buffers; make the record durable
                last_beat = now
            time.sleep(max(0.0, 1.0 / RATE))
    except KeyboardInterrupt:
        pass
    finally:
        d.stop()


if __name__ == "__main__":
    main()
