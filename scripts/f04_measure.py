"""F04 measurement: R2 worst-case detection with the new warn/escalate thresholds.

Before: incident only at the 60 s contract limit (measured 59.5 s, zero margin).
After: warn at 50 %, escalate at 75 % of the contract.
"""

import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.heartbeat import HeartbeatMonitor

OUT = os.path.join("artifacts", "f04_r2_margin.json")


def measure(trials: int = 20, timeout_s: float = 60.0, step_s: float = 0.25) -> dict:
    warn, incident, kinds = [], [], {}
    for _ in range(trials):
        now = [0.0]
        mon = HeartbeatMonitor(timeout_s=timeout_s, now_fn=lambda: now[0])
        for src in ("win.etw.ti", "win.amsi", "linux.ebpf", "linux.auditd"):
            mon.register(src)
        for src in ("win.amsi", "linux.ebpf", "linux.auditd"):
            mon.beat(src)
        t0 = now[0]
        saw_warn = None
        while now[0] - t0 < 120:
            now[0] += step_s
            opened = mon.check()
            if mon.warnings and saw_warn is None:
                saw_warn = round(now[0] - t0, 2)
            if opened:
                warn.append(saw_warn)
                incident.append(round(now[0] - t0, 2))
                kinds[opened[0].kind] = kinds.get(opened[0].kind, 0) + 1
                break
            for src in ("win.amsi", "linux.ebpf", "linux.auditd"):
                mon.beat(src)
    worst = max(incident)
    return {
        "trials": trials, "detected": len(incident), "contract_s": timeout_s,
        "warn_after_s": round(timeout_s * 0.5, 2),
        "escalate_after_s": round(timeout_s * 0.75, 2),
        "warn_latency_s_max": max(warn) if warn else None,
        "incident_latency_s_p50": round(statistics.median(incident), 2),
        "incident_latency_s_max": worst,
        "incident_kinds": kinds,
        "margin_s": round(timeout_s - worst, 2),
        "margin_pct": round(100.0 * (timeout_s - worst) / timeout_s, 1),
        "within_contract": worst <= timeout_s,
        "target_margin_25pct": worst <= timeout_s * 0.75 + step_s,
    }


if __name__ == "__main__":
    report = measure()
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, ensure_ascii=False))
