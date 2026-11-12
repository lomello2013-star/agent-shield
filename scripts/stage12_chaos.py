"""Stage 12 chaos: all Windows sources + fault injections in one run, R-metrics verified.

Lanes:
  * real System-log records (7045/7040/1102) via `win.eventlog`;
  * real Defender records (5001/5007/5010/1112/1116/1117) via `win.defender`;
  * synthetic event storm for R8 (explicitly labelled synthetic);
  * injections: source silence (R2), bad config/safe mode, audit-chain tamper (R10),
    update+rollback (R6), watchdog restart (R3), clock jump.

Linux lanes (eBPF exec/LSM/net) are measured by their own scripts; this harness does
not pretend to cover them.

Writes artifacts/stage12_chaos.json.
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402
from core.updater import DualSlot  # noqa: E402
from core.watchdog import ProcessHandle, Supervisor  # noqa: E402
from core.winsource import WindowsEventLogSource  # noqa: E402

OUT = os.path.join(HERE, "artifacts", "stage12_chaos.json")
HOST = HostContext(host_id="host-chaos", os="windows", version="10.0.19045", arch="x64")
DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational"


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


class Child(ProcessHandle):
    def __init__(self):
        self.proc = subprocess.Popen([sys.executable, "-c",
                                      "import time\nwhile True: time.sleep(0.05)"])

    def poll(self):
        return self.proc.poll()

    def terminate(self):
        self.proc.terminate()


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="aidf_chaos12_")
    cfg = DaemonConfig(sources=["win.eventlog", "win.defender"],
                       thresholds={"heartbeat_timeout_s": 2.0, "alert_budget": 500,
                                   "min_confidence": 0.5},
                       queue={"capacity": 5000})
    d = Daemon(os.path.join(tmp, "daemon"), config=cfg, host=HOST,
               rules_path=os.path.join(HERE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()

    report: dict[str, object] = {"environment": {"python": sys.version.split()[0]}}

    # ---------------- lane A: real System log ----------------
    system_src = WindowsEventLogSource("System", (7045, 7040, 1102), max_events=80)
    system_events = system_src.poll()
    # ---------------- lane B: real Defender log ----------------
    defender_src = WindowsEventLogSource(DEFENDER_LOG, (5001, 5007, 5010, 5012, 1116, 1117),
                                         max_events=80)
    defender_events = defender_src.poll()

    lat = []
    for record in system_events:
        d.submit("win.eventlog", record.to_raw())
        t0 = time.perf_counter(); d.tick(); lat.append((time.perf_counter() - t0) * 1000)
    for record in defender_events:
        d.submit("win.defender", record.to_raw())
        t0 = time.perf_counter(); d.tick(); lat.append((time.perf_counter() - t0) * 1000)
    report["sources"] = {
        "system_events": len(system_events), "defender_events": len(defender_events),
        "verdicts_after_sources": d.verdict_count,
        "rule_hits": d.engine.counts(),
        "tick_ms_p50": round(statistics.median(lat), 3) if lat else None,
        "tick_ms_p95": p95(lat),
        "ingest_received": d.pipeline.ingest.received,
        "lost": d.pipeline.ingest.lost,
    }

    # ---------------- R2: silent source ----------------
    # Beat every source first: otherwise an already-stale source makes the check
    # report "degraded" immediately and the number would be meaningless.
    d.heartbeat.timeout_s = 0.2
    for source in ("win.eventlog", "win.defender"):
        d.heartbeat.beat(source)
    d.tick()
    t0 = time.perf_counter()
    detected = None
    while time.perf_counter() - t0 < 5:
        d.tick()
        if d.health()["status"] == "degraded":
            detected = time.perf_counter() - t0
            break
        time.sleep(0.01)
    report["R2_silent_source"] = {"timeout_s": 0.2,
                                  "detection_s": round(detected, 3) if detected else None,
                                  "detected": detected is not None,
                                  "note": "silence measured from a fresh beat of all sources"}

    # ---------------- safe mode: bad config, LKG preserved ----------------
    good_lkg = d.safe_mode.load_lkg()
    bad = DaemonConfig(thresholds={"alert_budget": -1}).as_payload()
    res = d.safe_mode.apply(bad, dry_run=False)
    report["safe_mode"] = {"accepted": res.accepted, "safe_mode": d.safe_mode.is_safe,
                           "lkg_unchanged": d.safe_mode.load_lkg() == good_lkg}

    # ---------------- R8: synthetic storm with a paused consumer ----------------
    before = d.pipeline.ingest.stats()
    for i in range(20000):
        d.pipeline.submit_raw("win.eventlog", {
            "category": "registry.change", "action": "set_value",
            "path": rf"HKLM\SOFTWARE\Test\Value{i}", "event_id": 9999,
            "provider": "chaos", "record_id": i, "ts": "2026-11-12T00:00:00Z", "data": {}})
    mid = d.pipeline.ingest.stats()
    while d.pipeline.ingest.backlog_events() > 0:
        d.tick()
    after = d.pipeline.ingest.stats()
    report["R8_storm"] = {"submitted": 20000, "backlog_before_drain": mid["backlog"],
                          "spilled_before_drain": mid["spilled_pending"],
                          "lost": after["lost"], "ledger_ok": d.pipeline.ingest.ledger_ok(),
                          "received_total": after["received"], "delivered": after["delivered"]}

    # ---------------- R10: audit chain tamper ----------------
    with open(d.log.path, "a", encoding="utf-8") as fh:
        fh.write('{"forged": true}\n')
    t0 = time.perf_counter()
    health = d.health()
    report["R10_tamper"] = {"audit_chain_ok": health["audit_chain_ok"],
                            "detect_ms": round((time.perf_counter() - t0) * 1000, 3)}

    # ---------------- R6: update + rollback with health regression ----------------
    slots = DualSlot(os.path.join(tmp, "slots"))
    slots.stage("1.0.1", {"bin/aidfd": b"v2"})
    slots.activate("B", "1.0.1")
    active_before = slots.pointer()["slot"]
    rolled = slots.update_with_health_gate("1.0.2", {"bin/aidfd": b"v3"}, health=lambda: False)
    active_after = slots.pointer()["slot"]
    report["R6_update"] = {"active_before_failed_update": active_before,
                           "regression_result": rolled["result"],
                           "active_after_rollback": active_after,
                           "rolled_back": rolled["result"] == "rolled_back",
                           "state_restored": active_after == active_before}

    # ---------------- R3: watchdog restart ----------------
    spawn_times = []
    crash_times = []

    def spawn():
        spawn_times.append(time.perf_counter())
        return Child()

    sup = Supervisor(spawn=spawn, backoff=(0.0,), max_failures=20)
    sup.tick()
    child = sup.handle
    child.proc.kill()
    crash_times.append(time.perf_counter())
    deadline = time.perf_counter() + 10
    while sup.starts < 2 and time.perf_counter() < deadline:
        sup.tick()
        time.sleep(0.005)
    restarted = sup.starts >= 2
    mttr_ms = round((spawn_times[1] - crash_times[0]) * 1000, 1) if restarted else None
    if sup.handle is not None:
        sup.handle.proc.kill()
    report["R3_watchdog"] = {"restarted": restarted, "mttr_ms": mttr_ms,
                             "target_ms": 30000,
                             "within_target": bool(mttr_ms and mttr_ms < 30000)}

    # ---------------- clock jump ----------------
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
    d.log.flush()
    jumps = sum(1 for line in open(d.log.path, encoding="utf-8") if '"clock_jump"' in line)
    report["clock_jump"] = {"logged": jumps > 0}

    final = d.health()
    report["final"] = {"lost": final["ingest"]["lost"], "ledger_ok": final["ledger_ok"],
                       "verdicts": final["verdicts"], "alerts": final["alerts"],
                       "containments": final["containments"],
                       "integrity_ok": final["integrity_ok"]}
    d.stop()

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
