"""Measure supervisor behaviour on a *real* daemon child killed with SIGKILL-like force.

For each of K rounds: wait until the child reports READY, record its pid, kill it,
wait for the supervisor to spawn a replacement that reports READY, and record the delay.
Then verify that the audit chain across all restarts is intact and longer than one
child could have produced.

Writes artifacts/supervisor_measure.json.
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

from core.supervisor import Handle, Supervisor, SupervisorConfig  # noqa: E402

OUT = os.path.join(HERE, "artifacts", "supervisor_measure.json")
PY = sys.executable
ROUNDS = int(os.environ.get("KILL_ROUNDS", "3"))


class PopenHandle:
    def __init__(self, root: str, ready: str):
        self.ready = ready
        if os.path.exists(ready):
            os.remove(ready)
        self.proc = subprocess.Popen([PY, os.path.join(HERE, "scripts", "daemon_child.py")],
                                     env=dict(os.environ, AIDF_CHILD_ROOT=root,
                                              AIDF_CHILD_READY_FILE=ready,
                                              PYTHONIOENCODING="utf-8"),
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
            time.sleep(0.01)
        return None


def main() -> int:
    root = tempfile.mkdtemp(prefix="aidf_sup_")
    ready = os.path.join(root, "ready.txt")
    handles: list[PopenHandle] = []

    def spawn() -> PopenHandle:
        handle = PopenHandle(root, ready)
        handles.append(handle)
        return handle

    sup = Supervisor(spawn=spawn,
                     config=SupervisorConfig(max_restarts=5, window_s=600,
                                             backoff_base_s=0.5, backoff_max_s=5,
                                             healthy_after_s=1))
    sup.start()
    startup_ms = handles[0].wait_ready()
    rounds = []
    for index in range(1, ROUNDS + 1):
        current = handles[-1]
        pid = current.proc.pid
        killed_at = time.perf_counter()
        current.proc.kill()                      # hard kill: no graceful shutdown
        current.proc.wait(timeout=10)
        restarted = False
        deadline = time.time() + 30
        while time.time() < deadline:
            # drive the supervisor until a new, ready child appears
            status = sup.check()
            if handles[-1] is not current:
                if handles[-1].wait_ready(timeout=10) is not None:
                    restarted = True
                break
            time.sleep(0.005)
        delay_ms = round((time.perf_counter() - killed_at) * 1000, 1)
        rounds.append({"round": index, "killed_pid": pid, "restarted": restarted,
                       "restart_latency_ms": delay_ms,
                       "supervisor": status})

    # audit continuity across restarts (the daemon keeps its chain in audit/chain.jsonl)
    from core.selfprotect import HashChainLog
    log_path = os.path.join(root, "daemon", "audit", "chain.jsonl")
    if not os.path.exists(log_path):
        for base, _dirs, files in os.walk(root):
            if "chain.jsonl" in files:
                log_path = os.path.join(base, "chain.jsonl")
                break
    chain = {"ok": None, "records": 0}
    lifecycle = {"starts": 0, "stops": 0}
    if os.path.exists(log_path):
        log = HashChainLog(log_path, anchor_path=log_path.replace("chain.jsonl",
                                                                  "anchor.json"))
        state = log.verify()
        chain = {"ok": state.ok, "records": state.records}
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("type") == "daemon_start":
                    lifecycle["starts"] += 1
                elif record.get("type") == "daemon_stop":
                    lifecycle["stops"] += 1
        lifecycle["unclean_restarts"] = max(0, lifecycle["starts"] - lifecycle["stops"])
    sup.stop()

    report = {
        "rounds": rounds,
        "restarts_observed": sum(1 for r in rounds if r["restarted"]),
        "max_restart_latency_ms": max((r["restart_latency_ms"] for r in rounds), default=None),
        "median_restart_latency_ms": sorted(r["restart_latency_ms"] for r in rounds)[
            len(rounds) // 2] if rounds else None,
        "startup_ms": startup_ms,
        "audit_chain": chain,
        "lifecycle": lifecycle,
        "audit_log": log_path,
        "note": "child is killed with kill(), i.e. no graceful shutdown — the same shape "
                "as a native crash; the supervisor is what keeps the service alive",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
