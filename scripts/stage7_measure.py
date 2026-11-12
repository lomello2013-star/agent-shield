"""Stage 7 measurement: reversible response actions, rollback integrity, E10 contain time.

Writes artifacts/stage7_report.json. Uses real child processes (suspend/resume)
and real files (quarantine/restore); no privilege escalation is required.
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.confirm import ConfirmationManager
from core.response import CanaryStore, ProcessController, QuarantineStore, ResponseExecutor
from schemas.v3 import Action

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "artifacts", "stage7_report.json")
KEY = b"k" * 32


def p95(values):
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def measure_suspend_resume(cycles: int = 20) -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_s7p_")
    flag = os.path.join(tmp, "progress.bin")
    code = ("import sys,time\n"
            "f=open(sys.argv[1],'ab')\n"
            "while True:\n"
            "    f.write(b'x'); f.flush(); time.sleep(0.02)\n")
    child = subprocess.Popen([sys.executable, "-c", code, flag])
    ctl = ProcessController()
    suspend_ms, resume_ms, frozen_ok = [], [], 0
    try:
        time.sleep(0.4)
        for _ in range(cycles):
            size = os.path.getsize(flag)
            t0 = time.perf_counter(); ctl.suspend(child.pid)
            suspend_ms.append((time.perf_counter() - t0) * 1000)
            time.sleep(0.15)
            frozen = os.path.getsize(flag)
            time.sleep(0.25)
            if os.path.getsize(flag) == frozen and frozen >= size:
                frozen_ok += 1
            t0 = time.perf_counter(); ctl.resume(child.pid)
            resume_ms.append((time.perf_counter() - t0) * 1000)
            time.sleep(0.15)
    finally:
        child.kill()
        child.wait(timeout=5)
    return {"cycles": cycles, "freeze_verified": frozen_ok,
            "freeze_rate": round(frozen_ok / cycles, 3),
            "suspend_ms_p50": round(statistics.median(suspend_ms), 3),
            "suspend_ms_p95": p95(suspend_ms),
            "resume_ms_p50": round(statistics.median(resume_ms), 3),
            "resume_ms_p95": p95(resume_ms),
            "target_ms": 5000, "within_target": p95(suspend_ms) < 5000}


def measure_quarantine(files: int = 100) -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_s7q_")
    store = QuarantineStore(os.path.join(tmp, "q"), key=KEY)
    src = os.path.join(tmp, "src")
    os.makedirs(src, exist_ok=True)
    hashes = {}
    put_ms, restore_ms, restored_ok = [], [], 0
    for i in range(files):
        path = os.path.join(src, f"sample_{i}.bin")
        payload = os.urandom(2048) + str(i).encode()
        with open(path, "wb") as fh:
            fh.write(payload)
        import hashlib
        hashes[i] = hashlib.sha256(payload).hexdigest()
        t0 = time.perf_counter()
        entry = store.put(path, "spike")
        put_ms.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        dest = store.restore(entry.quarantine_id)
        restore_ms.append((time.perf_counter() - t0) * 1000)
        import hashlib as h2
        if h2.sha256(open(dest, "rb").read()).hexdigest() == hashes[i]:
            restored_ok += 1
    return {"files": files, "restored_intact": restored_ok,
            "integrity_rate": round(restored_ok / files, 3),
            "put_ms_p50": round(statistics.median(put_ms), 3), "put_ms_p95": p95(put_ms),
            "restore_ms_p50": round(statistics.median(restore_ms), 3),
            "restore_ms_p95": p95(restore_ms), "target_rollback_rate": 1.0}


def measure_contain_latency(cycles: int = 20) -> dict:
    """verdict -> confirmation -> quarantine execution, end-to-end (E10 contain <= 5 s)."""
    tmp = tempfile.mkdtemp(prefix="aidf_s7c_")
    store = QuarantineStore(os.path.join(tmp, "q"), key=KEY)
    mgr = ConfirmationManager()
    ex = ResponseExecutor(mgr, quarantine=store)
    latencies, executed = [], 0
    for i in range(cycles):
        path = os.path.join(tmp, f"threat_{i}.bin")
        with open(path, "wb") as fh:
            fh.write(b"malicious")
        t0 = time.perf_counter()
        conf = mgr.request(f"verdict-{i}", level="normal")
        mgr.resolve(conf.confirmation_id, "approved", decided_by="policy")
        action = Action.model_validate({
            "action_id": str(uuid.uuid4()), "trace_id": str(uuid.uuid4()),
            "verdict_id": str(uuid.uuid4()), "type": "quarantine", "target": path,
            "reversible": True, "requires_confirmation": True,
            "confirmation_id": str(conf.confirmation_id), "platform_effect": "quarantine",
        })
        result = ex.execute(action)
        latencies.append((time.perf_counter() - t0) * 1000)
        if result.status == "executed":
            executed += 1
    return {"cycles": cycles, "executed": executed,
            "contain_ms_p50": round(statistics.median(latencies), 3),
            "contain_ms_p95": p95(latencies), "target_ms": 5000,
            "within_target": p95(latencies) < 5000}


def measure_canary() -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_s7k_")
    store = CanaryStore(os.path.join(tmp, "canary"))
    files = store.create(5)
    t0 = time.perf_counter()
    clean = store.check()
    check_ms = (time.perf_counter() - t0) * 1000
    os.remove(files[0])
    broken = store.check()
    return {"canaries": 5, "clean_check_empty": clean == [], "check_ms": round(check_ms, 3),
            "deleted_detected": len(broken), "detection_rate": len(broken)}


def measure_refusals() -> dict:
    mgr = ConfirmationManager(operator_present=False)
    ex = ResponseExecutor(mgr)
    refused = 0
    results = []
    for action_type, kwargs in (("terminate", {"reversible": False}),
                                ("suspend", {"requires_confirmation": True}),
                                ("block_network", {})):
        action = Action.model_validate({
            "action_id": str(uuid.uuid4()), "trace_id": str(uuid.uuid4()),
            "verdict_id": str(uuid.uuid4()), "type": action_type, "target": "1234",
            "reversible": kwargs.get("reversible", True),
            "requires_confirmation": kwargs.get("requires_confirmation", False),
        })
        result = ex.execute(action)
        results.append({"type": action_type, "status": result.status, "error": result.error})
        if result.status in ("refused", "failed"):
            refused += 1
    return {"cases": results, "blocked": refused, "total": len(results),
            "block_rate": round(refused / len(results), 3)}


def main() -> None:
    report = {
        "environment": {"python": sys.version.split()[0], "platform": sys.platform},
        "suspend_resume": measure_suspend_resume(),
        "quarantine": measure_quarantine(),
        "contain_latency": measure_contain_latency(),
        "canary": measure_canary(),
        "refusals": measure_refusals(),
        "note": "irreversible actions are refused by design; no human-approval bypass exists",
    }
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
