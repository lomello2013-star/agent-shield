"""F11: does pydantic-core crash on its own under concurrent validation?

The soak crashes with a native access violation while threads validate events. This
script removes the whole daemon: only pydantic `Event.model_validate` runs, from several
threads, at full speed. If this reproduces 0xC0000005, the crash is in the validation
library (or its interaction with threads), not in our pipeline logic.

Usage: python scripts/f11_pydantic_stress.py
Env:   THREADS (default 4), DURATION_S (default 180)
Writes artifacts/f11_pydantic_stress.json on a clean exit; a native crash leaves no file.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from schemas.v3 import Event  # noqa: E402

OUT = os.path.join(HERE, "artifacts", "f11_pydantic_stress.json")
THREADS = int(os.environ.get("THREADS", "4"))
DURATION = float(os.environ.get("DURATION_S", "180"))


def payload() -> dict:
    return {
        "schema_version": "3.0", "event_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()),
        "ts_event": datetime.now(timezone.utc).isoformat(),
        "ts_ingest": datetime.now(timezone.utc).isoformat(),
        "raw_ref": "raw/s",
        "platform": "windows", "source": "win.eventlog", "layer": "user",
        "category": "file.write", "action": "write",
        "actor": {"pid": 1, "ppid": 0, "name": "a", "path": "a",
                  "cmdline_hash": "ab" * 32, "cmdline_redacted": "a"},
        "object": {"type": "file", "path": "x"},
        "host": {"host_id": "s", "os": "windows", "version": "10", "arch": "x64"},
    }


def main() -> None:
    stop = threading.Event()
    validated = [0] * THREADS
    errors: list[str] = []

    def worker(index: int) -> None:
        base = payload()
        while not stop.is_set():
            try:
                Event.model_validate(base)
                base["ts_ingest"] = datetime.now(timezone.utc).isoformat()
                validated[index] += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}")
                return

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(THREADS)]
    for thread in threads:
        thread.start()
    started = time.time()
    time.sleep(DURATION)
    stop.set()
    for thread in threads:
        thread.join(timeout=5)
    total = sum(validated)
    report = {
        "threads": THREADS, "duration_s": DURATION, "validated": total,
        "rate_per_s": round(total / max(1e-9, time.time() - started), 0),
        "errors": errors[:5],
        "note": "no daemon here: only Event.model_validate from several threads",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
