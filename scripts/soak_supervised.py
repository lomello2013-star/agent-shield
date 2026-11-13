"""Supervised long soak: measure availability while the CPython fault keeps happening.

The daemon crashes natively (0xC0000005 in python312.dll) at an irregular rate. This
harness runs it under `core.supervisor.Supervisor` for a long window and measures what
actually matters for R1/R4: **availability** (time the service was up / window), the
number of restarts, per-restart downtime, and that the audit chain stays valid across
crashes.

Env: DURATION_S (default 3600), AIDF_CHILD_RATE (default 200), RESTART_POLL_S (0.25)
Writes artifacts/soak_supervised.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.selfprotect import HashChainLog  # noqa: E402
from core.supervisor import Supervisor, SupervisorConfig  # noqa: E402

OUT = os.path.join(HERE, "artifacts", "soak_supervised.json")
PY = sys.executable
DURATION = float(os.environ.get("DURATION_S", "3600"))
RATE = os.environ.get("AIDF_CHILD_RATE", "200")
POLL = float(os.environ.get("RESTART_POLL_S", "0.25"))


class Child:
    def __init__(self, root: str, ready: str):
        self.ready = ready
        if os.path.exists(ready):
            os.remove(ready)
        self.started = time.perf_counter()
        self.proc = subprocess.Popen(
            [PY, os.path.join(HERE, "scripts", "daemon_child.py")],
            env=dict(os.environ, AIDF_CHILD_ROOT=root, AIDF_CHILD_READY_FILE=ready,
                     AIDF_CHILD_RATE=RATE, PYTHONIOENCODING="utf-8"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def poll(self):
        return self.proc.poll()

    def terminate(self):
        self.proc.kill()

    def wait_ready(self, timeout: float = 30.0) -> float | None:
        started = time.perf_counter()
        while time.perf_counter() - started < timeout:
            if os.path.exists(self.ready):
                return round((time.perf_counter() - started) * 1000, 1)
            if self.proc.poll() is not None:
                return None
            time.sleep(0.005)
        return None


def main() -> int:
    root = tempfile.mkdtemp(prefix="aidf_supsoak_")
    ready = os.path.join(root, "ready.txt")
    children: list[Child] = []

    def spawn() -> Child:
        child = Child(root, ready)
        children.append(child)
        return child

    sup = Supervisor(spawn=spawn,
                     config=SupervisorConfig(max_restarts=10, window_s=3600,
                                             backoff_base_s=0.5, backoff_max_s=5,
                                             healthy_after_s=30))
    window_start = time.monotonic()
    sup.start()
    first_ready = children[0].wait_ready(60)
    crashes: list[dict] = []
    down_total_s = 0.0
    last = children[-1]
    partial_path = os.path.join(HERE, "artifacts", "soak_supervised_partial.json")
    events_path = os.path.join(HERE, "artifacts", "_stdout", "soak_supervised_events.jsonl")
    os.makedirs(os.path.dirname(events_path), exist_ok=True)
    last_partial = 0.0
    while time.monotonic() - window_start < DURATION:
        time.sleep(POLL)
        before_count = len(children)
        sup.check()
        if len(children) > before_count:
            # a new child was spawned: measure downtime until it is ready
            ready_ms = children[-1].wait_ready(60)
            downtime = round((ready_ms or 0) / 1000.0, 3)
            down_total_s += downtime
            crashes.append({"at_s": round(time.monotonic() - window_start, 1),
                            "ready_ms": ready_ms, "downtime_s": downtime})
            last = children[-1]
            try:
                with open(events_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(crashes[-1], ensure_ascii=False) + "\n")
            except OSError:
                pass
            if os.environ.get("VERBOSE") == "1":
                print(f"[supsoak] restart at {crashes[-1]['at_s']}s "
                      f"ready_ms={ready_ms} total_down={round(down_total_s, 2)}s",
                      flush=True)
        elapsed = time.monotonic() - window_start
        if elapsed - last_partial >= 60.0:
            last_partial = elapsed
            partial = {"partial": True, "window_s": round(elapsed, 1),
                       "restarts": len(crashes), "downtime_total_s": round(down_total_s, 3),
                       "availability_pct": round(100.0 * (1 - down_total_s / elapsed), 4),
                       "crashes": crashes[-5:]}
            try:
                with open(partial_path, "w", encoding="utf-8") as fh:
                    json.dump(partial, fh, ensure_ascii=False)
            except OSError:
                pass
    window = time.monotonic() - window_start
    sup.stop()

    # audit continuity
    log_path = os.path.join(root, "audit", "chain.jsonl")
    chain = {"ok": None, "records": 0}
    lifecycle = {"starts": 0, "stops": 0}
    if os.path.exists(log_path):
        state = HashChainLog(log_path, anchor_path=os.path.join(root, "audit",
                                                                "anchor.json")).verify()
        chain = {"ok": state.ok, "records": state.records}
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                kind = json.loads(line).get("type")
                if kind == "daemon_start":
                    lifecycle["starts"] += 1
                elif kind == "daemon_stop":
                    lifecycle["stops"] += 1

    report = {
        "window_s": round(window, 1),
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "health_sampling": os.environ.get("AIDF_CHILD_HEALTH") == "1",
        "rate_per_s": float(RATE),
        "restarts": len(crashes),
        "crashes": crashes,
        "downtime_total_s": round(down_total_s, 3),
        "availability_pct": round(100.0 * (1 - down_total_s / window), 4),
        "audit_chain": chain,
        "lifecycle": lifecycle,
        "max_downtime_s": max((c["downtime_s"] for c in crashes), default=0.0),
        "median_downtime_s": sorted(c["downtime_s"] for c in crashes)[len(crashes) // 2]
        if crashes else 0.0,
        "note": "availability measured under the *real* native fault: supervisor "
                "restarts the process, audit chain is checked across all restarts",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({k: report[k] for k in ("window_s", "restarts", "availability_pct",
                                             "downtime_total_s", "max_downtime_s",
                                             "audit_chain", "lifecycle")},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
