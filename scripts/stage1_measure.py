"""Stage 1 gate measurement: R2/R3/R4/R6/R8/R9/R10 via fault injection.

Everything here is measured, not asserted in prose. Output: artifacts/stage1_report.json
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.confirm import ConfirmationManager
from core.counters import LossCounters
from core.heartbeat import HeartbeatMonitor
from core.ingest import P0_PROCESS, P1_FILE, P2_NOISE, IngestPipeline
from core.policy import PolicyViolation, snapshot, verify_immutable
from core.updater import DualSlot, sha256_bytes
from core.watchdog import ProcessHandle, Supervisor

REPORT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "artifacts", "stage1_report.json")
results: dict[str, object] = {}


def p95(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, int(len(s) * 0.95))
    return round(s[idx], 3)


# ------------------------------------------------------------------ R2
def measure_r2(trials: int = 20, timeout_s: float = 59.0, check_interval_s: float = 0.5) -> dict:
    """Silent-source detection: how long until an incident, over N trials.

    F04: the monitor warns at 50 % of the contract and escalates at 75 %, so the
    worst-case detection keeps a margin instead of landing on the 60 s limit.
    """
    latencies, detected = [], 0
    warn_latencies: list[float] = []
    kinds: dict[str, int] = {}
    for _ in range(trials):
        now = [0.0]
        mon = HeartbeatMonitor(timeout_s=timeout_s, now_fn=lambda: now[0])
        mon.register("win.etw.ti"); mon.register("win.amsi")
        mon.register("linux.ebpf"); mon.register("linux.auditd")
        mon.beat("win.amsi"); mon.beat("linux.ebpf"); mon.beat("linux.auditd")
        # win.etw.ti dies silently here
        t0 = now[0]
        while now[0] - t0 < 120:
            now[0] += check_interval_s
            opened = mon.check()
            if opened:
                detected += 1
                latencies.append(round(now[0] - t0, 3))
                kinds[opened[0].kind] = kinds.get(opened[0].kind, 0) + 1
                if mon.warnings:
                    warn_latencies.append(mon.warnings[0].silent_for_s)
                break
            mon.beat("win.amsi"); mon.beat("linux.ebpf"); mon.beat("linux.auditd")
    return {"trials": trials, "detected": detected, "detection_rate": detected / trials,
            "max_latency_s": max(latencies) if latencies else None,
            "p95_latency_s": p95(latencies), "target_s": 60.0,
            "max_warn_s": max(warn_latencies) if warn_latencies else None,
            "incident_kinds": kinds,
            "margin_s": round(60.0 - max(latencies), 3) if latencies else None,
            "margin_pct": round(100.0 * (60.0 - max(latencies)) / 60.0, 1) if latencies else None,
            "within_target": detected == trials and max(latencies or [999]) <= 60.0}


# ------------------------------------------------------------------ R3
class PopenHandle(ProcessHandle):
    def __init__(self, cmd: list[str]):
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def poll(self):
        return self.proc.poll()

    def terminate(self):
        self.proc.terminate()


def measure_r3(cycles: int = 10) -> dict:
    """MTTR: crash -> respawn latency, real subprocesses, default backoff."""
    spawn_times: list[float] = []
    crash_times: list[float] = []

    def spawn():
        spawn_times.append(time.perf_counter())
        return PopenHandle([sys.executable, "-c", "import sys; sys.exit(1)"])

    sup = Supervisor(spawn=spawn, backoff=(0.0, 0.02, 0.05, 0.1), max_failures=cycles + 5)
    deadline = time.perf_counter() + 30
    sup.tick()
    while len(crash_times) < cycles and time.perf_counter() < deadline:
        before = sup.crashes
        sup.tick()
        if sup.crashes > before:
            crash_times.append(time.perf_counter())
        time.sleep(0.005)
    mttrs = []
    for i in range(1, min(len(spawn_times), len(crash_times) + 1)):
        if i < len(crash_times):
            mttrs.append(round((spawn_times[i] - crash_times[i - 1]) * 1000, 1))
    return {"cycles": len(mttrs), "mttr_ms_p50": round(statistics.median(mttrs), 1) if mttrs else None,
            "mttr_ms_p95": p95(mttrs), "target_s": 30.0,
            "within_target": bool(mttrs) and p95(mttrs) <= 30_000,
            "crashes": sup.crashes, "starts": sup.starts}


# ------------------------------------------------------------------ R4
def measure_r4(iterations: int = 20) -> dict:
    """Platform session survivability: no unhandled failure across forced faults."""
    survived = 0
    for _ in range(iterations):
        try:
            now = [0.0]
            mon = HeartbeatMonitor(timeout_s=5, now_fn=lambda: now[0])
            mon.register("src", probe=lambda: True)
            now[0] += 10
            mon.check()            # incident, not crash
            mon.beat("src")
            mon.probe("src")
            pipe = IngestPipeline(capacity=8, reserved_ratio=0.0)
            for i in range(50):
                pipe.submit("test", f"k{i}", priority=(P1_FILE if i % 2 else P0_PROCESS))
            pipe.drain(1000)
            survived += 1
        except Exception:
            pass
    return {"iterations": iterations, "survived": survived,
            "survival_rate": survived / iterations, "target": 0.999}


# ------------------------------------------------------------------ R6
def slot_fingerprint(ds: DualSlot, slot: str) -> str:
    """Fingerprint of a slot's manifest (files + hashes + version)."""
    path = os.path.join(ds._slot_dir(slot), "manifest.json")
    with open(path, "rb") as fh:
        return sha256_bytes(fh.read())


def measure_r6(cycles: int = 20, regressions: int = 5) -> dict:
    """Update success / rollback-to-identical-state, incl. induced regressions."""
    tmp = tempfile.mkdtemp(prefix="aidf_r6_")
    ds = DualSlot(tmp)
    updated = rolled_back = 0
    identical_after_rollback = 0
    payload = {"bin/aidfd": b"binary-v2", "rules/r.json": b'{"r":1}'}
    for i in range(cycles):
        before = slot_fingerprint(ds, ds.active_slot())
        regress = i < regressions
        res = ds.update_with_health_gate(f"1.{i}.0", payload, health=(lambda: not regress))
        if res["result"] == "updated":
            updated += 1
        else:
            rolled_back += 1
            after = slot_fingerprint(ds, ds.active_slot())
            if after == before:
                identical_after_rollback += 1
    return {"cycles": cycles, "updated": updated, "rolled_back": rolled_back,
            "induced_regressions": regressions,
            "rollback_state_identical": identical_after_rollback,
            "update_success_rate": updated / max(1, cycles - regressions),
            "rollback_rate": rolled_back / regressions,
            "target_update": 0.999, "target_rollback": 1.0}


# ------------------------------------------------------------------ R8
def measure_r8(total: int = 100_000, capacity: int = 10_000, stall_s: float = 0.0, fsync_every: int = 1) -> dict:
    """Loss under a mixed event storm, with a consumer that may stall."""
    tmp = tempfile.mkdtemp(prefix="aidf_r8_")
    spill = os.path.join(tmp, "spool", "events.jsonl")
    counters = LossCounters()
    pipe = IngestPipeline(capacity=capacity, spill_path=spill, reserved_ratio=0.2,
                          counters=counters, aggregation_window_s=0.2, spill_fsync_every=fsync_every)
    delivered = [0]
    stop = threading.Event()

    def consumer():
        while not stop.is_set():
            chunk = pipe.drain(500)
            delivered[0] += sum(r.count for r in chunk)
            if not chunk:
                time.sleep(0.001)

    th = threading.Thread(target=consumer, daemon=True)

    def producer():
        for i in range(total):
            if i % 10 == 0:
                pipe.submit("process.start", f"p{i}", priority=P0_PROCESS)
            elif i % 3 == 0:
                pipe.submit("file.write", f"f{i}", priority=P1_FILE)
            else:
                pipe.submit("auth.failure", "noise", priority=P2_NOISE)

    t0 = time.perf_counter()
    if stall_s > 0:
        producer()                     # no consumer yet -> forced overflow
        time.sleep(stall_s)
        th.start()
    else:
        th.start()
        producer()
    while pipe.backlog_events() > 0 and time.perf_counter() - t0 < 60:
        time.sleep(0.01)
    pipe.flush_aggregation(force=True)
    time.sleep(0.05)
    stop.set(); th.join(timeout=5)
    elapsed = time.perf_counter() - t0
    stats = pipe.stats()
    return {"total_submitted": total, "capacity": capacity, "stall_s": stall_s, "fsync_every": fsync_every,
            "delivered": stats["delivered"], "lost": stats["lost"],
            "spilled_pending": stats["spilled_pending"],
            "loss_ratio_pct": round(100.0 * stats["lost"] / total, 6),
            "target_loss_pct": 0.01,
            "ledger_ok": pipe.ledger_ok(),
            "throughput_ev_per_s": round(total / elapsed, 0),
            "elapsed_s": round(elapsed, 2)}


# ------------------------------------------------------------------ R9
def measure_r9(trials: int = 100) -> dict:
    """Fail-safe: timeouts reject; destructive without operator never executes."""
    now = [0.0]
    mgr = ConfirmationManager(default_timeout_s=30, operator_present=False, now_fn=lambda: now[0])
    timed_out_rejected = 0
    for i in range(trials):
        conf = mgr.request(f"act-{i}")
        now[0] += 31
        if mgr.expire() and conf.decision == "reject":
            timed_out_rejected += 1
    executed_without_operator = 0
    for i in range(20):
        conf = mgr.request(f"terminate-{i}", destructive=True)
        mgr.resolve(conf.confirmation_id, "approved")
        if mgr.executable(conf.confirmation_id):
            executed_without_operator += 1
    return {"timeouts": trials, "rejected_on_timeout": timed_out_rejected,
            "fail_safe_rate": timed_out_rejected / trials,
            "destructive_without_operator": 20,
            "executed_without_operator": executed_without_operator,
            "target": 1.0}


# ------------------------------------------------------------------ R10
def measure_r10(trials: int = 20) -> dict:
    """Tamper evidence: immutable policy change and slot file change detected."""
    policy_detected = 0
    for _ in range(trials):
        bad = snapshot()
        bad["MODELS_TRAIN_ON_DEVICE"] = True
        try:
            verify_immutable(bad)
        except PolicyViolation:
            policy_detected += 1
    tmp = tempfile.mkdtemp(prefix="aidf_r10_")
    ds = DualSlot(tmp)
    ds.stage("2.0.0", {"f": b"original"})
    slot_detected = 0
    for i in range(trials):
        path = os.path.join(ds._slot_dir("B"), "f")
        with open(path, "wb") as fh:
            fh.write(f"tamper-{i}".encode())
        if not ds.verify_slot("B"):
            slot_detected += 1
        ds.stage("2.0.0", {"f": b"original"})   # restore for next trial
    return {"trials": trials, "policy_tamper_detected": policy_detected,
            "slot_tamper_detected": slot_detected,
            "tamper_detection_rate": (policy_detected + slot_detected) / (2 * trials),
            "target": 1.0}


def main() -> None:
    t0 = time.perf_counter()
    results["environment"] = {"python": sys.version.split()[0], "platform": sys.platform,
                              "cpu": os.cpu_count()}
    results["R2_silent_source"] = measure_r2()
    results["R3_mttr"] = measure_r3()
    results["R4_session_survival"] = measure_r4()
    results["R6_update_rollback"] = measure_r6()
    results["R8_loss_storm_smooth"] = measure_r8(total=100_000, stall_s=0.0)
    results["R8_loss_storm_stalled_fsync1"] = measure_r8(total=100_000, stall_s=1.0, fsync_every=1)
    results["R8_loss_storm_stalled_fsync128"] = measure_r8(total=100_000, stall_s=1.0, fsync_every=128)
    results["R9_fail_safe"] = measure_r9()
    results["R10_tamper"] = measure_r10()
    results["total_runtime_s"] = round(time.perf_counter() - t0, 2)
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()


