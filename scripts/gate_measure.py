"""Stage 7b/gate measurement: Verdict -> Action gate, alert budget, PPV, E2E containment.

Writes artifacts/gate_report.json.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.confirm import ConfirmationManager
from core.gate import AlertBudget, PolicyGate, ppv
from core.ingest import IngestPipeline
from core.normalize import HostContext, Normalizer
from core.pipeline import Pipeline
from core.response import QuarantineStore, ResponseExecutor
from core.rules import RuleEngine, load_rules
from schemas.v3 import Action

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "artifacts", "gate_report.json")
RULES = load_rules([os.path.join(HERE, "rules", "base.json")])
HOST = HostContext(host_id="host-1", os="windows", version="10.0.19045", arch="x64")
KEY = b"k" * 32


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.t = start

    def __call__(self):
        return self.t


def lsass_event(i=0):
    return {"process_id": 500 + i, "parent_id": 4,
            "process_name": r"C:\Temp\dropper.exe", "cmdline": "dropper.exe",
            "target": r"C:\Windows\System32\lsass.exe", "category": "process.access",
            "action": "open_process"}


def runkey_event(i=0):
    return {"process_id": 600 + i, "parent_id": 4, "process_name": r"C:\Temp\p.exe",
            "target": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x",
            "category": "registry.change", "action": "set_value"}


def smb_event(i=0):
    return {"process_id": 700 + i, "parent_id": 4, "process_name": r"C:\Windows\System32\cmd.exe",
            "target": "10.0.0.5:445", "category": "net.connect", "action": "connect"}


EVENTS = {"lsass": lsass_event, "runkey": runkey_event, "smb": smb_event}


def make_pipeline(tmp):
    return Pipeline(
        normalizer=Normalizer(host=HOST, quarantine_path=os.path.join(tmp, "q.jsonl")),
        ingest=IngestPipeline(capacity=5000, reserved_ratio=0.2,
                              spill_path=os.path.join(tmp, "spool.jsonl")),
        engine=RuleEngine(RULES),
    )


def measure_gate_decisions(total: int = 20000) -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_gate_")
    pipe = make_pipeline(tmp)
    clock = FakeClock()
    gate = PolicyGate(budget=AlertBudget(per_window=1, window_s=14 * 86400, now_fn=clock))
    kinds = list(EVENTS.values())
    for i in range(total):
        if i % 50 == 0:
            pipe.submit_raw("win.etw.ti", kinds[i % 3](i))
    verdicts = []
    while True:
        chunk = pipe.run_once(500)
        if not chunk:
            break
        verdicts.extend(chunk)
    alerts = contains = downgraded = suppressed = 0
    for v in verdicts:
        decision = gate.decide(v, "host-1", f"target-{v.rule_id}")
        if decision.alert:
            alerts += 1
        if decision.actions:
            contains += 1
        if decision.reason == "contain_without_alert":
            downgraded += 1
        if decision.suppressed:
            suppressed += 1
    return {"events": total, "verdicts": len(verdicts), "alerts": alerts,
            "containments": contains,
            "budget_downgraded": downgraded,
            "suppressed": suppressed,
            "alerts_per_verdict": round(alerts / max(1, len(verdicts)), 4)}


def measure_14_day_budget() -> dict:
    from schemas.v3 import Verdict
    clock = FakeClock()
    gate = PolicyGate(budget=AlertBudget(per_window=1, window_s=14 * 86400, now_fn=clock))
    alerts = 0
    contains = 0
    for _ in range(14 * 24):             # 14 days, one verdict per hour
        clock.t += 3600
        v = Verdict.model_validate({
            "verdict_id": str(uuid.uuid4()), "trace_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()), "detector": "rule",
            "rule_id": "WIN-LSASS-ACCESS-004", "platform": "windows",
            "confidence": 1.0, "severity": "critical",
            "reason_code": "lsass_access", "reason_text": "test",
        })
        d = gate.decide(v, "host-1", f"pid:{uuid.uuid4()}")
        alerts += int(d.alert)
        contains += int(bool(d.actions))
    return {"days": 14, "verdicts": 14 * 24, "alerts": alerts, "containments": contains,
            "budget": 1, "alerts_within_budget": alerts <= 1}


def measure_ppv_table() -> list[dict]:
    rows = []
    prevalence = 0.001
    for label, tpr, fpr in (
        ("pe@0.1%FPR", 0.6656, 0.001),
        ("pe@0.5%FPR", 0.8056, 0.005),
        ("pe@1%FPR", 0.8616, 0.01),
        ("elf@0.5%FPR", 0.936, 0.005),
    ):
        value = ppv(tpr, fpr, prevalence)
        rows.append({"model": label, "tpr": tpr, "fpr": fpr,
                     "prevalence": prevalence, "ppv": round(value, 4),
                     "ppv_pct": round(100 * value, 2),
                     "passes_ppv_50": value >= 0.5,
                     "required_fpr_for_50pct": round(tpr * prevalence / (0.5 * (1 - prevalence)
                                                                        + 0.5 * tpr * prevalence), 6)})
    return rows


def measure_e2e_containment() -> dict:
    import subprocess
    tmp = tempfile.mkdtemp(prefix="aidf_e2e_")
    pipe = make_pipeline(tmp)
    store = QuarantineStore(os.path.join(tmp, "quarantine"), key=KEY)
    mgr = ConfirmationManager()
    executor = ResponseExecutor(mgr, quarantine=store)
    gate = PolicyGate(budget=AlertBudget(per_window=10, window_s=86400))

    # a real process to suspend (E2E must exercise a real action, not a no-op)
    child = subprocess.Popen([sys.executable, "-c",
                              "import time\nwhile True: time.sleep(0.05)"])
    threat = os.path.join(tmp, "dropper.exe")
    with open(threat, "wb") as fh:
        fh.write(b"MZ-malicious")
    try:
        pipe.submit_raw("win.etw.ti", {**lsass_event(), "process_name": threat})
        pipe.submit_raw("win.etw.ti", runkey_event())
        pipe.submit_raw("win.etw.ti", smb_event())

        t0 = time.perf_counter()
        verdicts = pipe.run_once(100)
        results = []
        for v in verdicts:
            decision = gate.decide(v, "host-1", threat)
            for action_type in decision.actions:
                conf = mgr.request(f"{v.verdict_id}", level="normal")
                mgr.resolve(conf.confirmation_id, "approved", decided_by="policy")
                action = Action.model_validate({
                    "action_id": str(uuid.uuid4()), "trace_id": str(v.trace_id),
                    "verdict_id": str(v.verdict_id), "type": action_type,
                    "target": threat if action_type == "quarantine" else str(child.pid),
                    "reversible": True, "requires_confirmation": True,
                    "confirmation_id": str(conf.confirmation_id),
                    "platform_effect": "policy-gate",
                })
                res = executor.execute(action)
                results.append({"type": action_type, "status": res.status})
        elapsed_ms = (time.perf_counter() - t0) * 1000
    finally:
        child.kill()
        child.wait(timeout=5)
    executed = sum(1 for r in results if r["status"] == "executed")
    return {"verdicts": len(verdicts), "actions_attempted": len(results),
            "actions_executed": executed, "results": results,
            "quarantined": len(store.list()),
            "e2e_ms": round(elapsed_ms, 3),
            "contain_within_5s": elapsed_ms < 5000}


def main() -> None:
    report = {
        "environment": {"python": sys.version.split()[0]},
        "gate_decisions": measure_gate_decisions(),
        "budget_14d": measure_14_day_budget(),
        "ppv": measure_ppv_table(),
        "e2e": measure_e2e_containment(),
        "note": "containment is gated on rule verdicts only; ML stays shadow until "
                "calibration + FP budget are proven on a pilot",
    }
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
