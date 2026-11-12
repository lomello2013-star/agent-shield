"""F02 + F03 measurement: does demoting CORR-109 and requiring provenance remove
the false-positive alert without losing the real detection?

Three scenarios, all through the same rule engine *and* the policy gate:
  A  JIT only (mprotect, no cross-process write)
  B  supervisor + JIT, untrusted path, provenance known   -> the real pattern
  C  supervisor + JIT, path unresolved (provenance unknown) -> must not alert
"""

import json
import os
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.gate import AlertBudget, PolicyGate  # noqa: E402
from core.normalize import HostContext, Normalizer  # noqa: E402
from core.rules import RuleEngine, load_rules  # noqa: E402
from schemas.v3 import Event  # noqa: E402

OUT = os.path.join("artifacts", "f02_f03_measure.json")
HOST = HostContext(host_id="f02", os="linux", version="26.04", arch="x64", kernel="6.18")


def normalizer():
    return Normalizer(HOST)


def event(payload: dict) -> Event:
    base = {
        "schema_version": "3.0", "event_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()),
        "ts_event": datetime.now(timezone.utc).isoformat(),
        "ts_ingest": datetime.now(timezone.utc).isoformat(),
        "raw_ref": "raw/f02",
    }
    base.update(payload)
    return Event.model_validate(base)


def stream(norm: Normalizer, supervisor_pid: int, child_pid: int,
           exe: str, writes: int, execs: int) -> list[Event]:
    out = []
    for _ in range(writes):
        out.append(event(norm.normalize("linux.memory", {
            "pid": supervisor_pid, "ppid": 1, "target": child_pid,
            "comm": "sup", "exe": exe, "bytes": 1})))
    for _ in range(execs):
        out.append(event(norm.normalize("linux.mprotect", {
            "pid": child_pid, "ppid": supervisor_pid, "comm": "jit",
            "exe": "/usr/lib/jit", "anon": 1, "len": 4096})))
    return out


def run(name: str, events: list[Event]) -> dict:
    engine = RuleEngine(load_rules(["rules/base.json"]))
    gate = PolicyGate(budget=AlertBudget(per_window=100, window_s=3600))
    verdicts, alerts = [], []
    for ev in events:
        for v in engine.evaluate(ev):
            verdicts.append(v)
            decision = gate.decide(v, "f02")
            if decision.alert:
                alerts.append({"rule": v.rule_id, "severity": v.severity,
                               "actions": list(decision.actions)})
    return {"scenario": name,
            "verdicts": [{"rule": v.rule_id, "severity": v.severity} for v in verdicts],
            "alerts": alerts, "alert_count": len(alerts)}


def main() -> None:
    norm = normalizer()
    jit_only = [event(norm.normalize("linux.mprotect", {
        "pid": 5000, "ppid": 1, "comm": "jit", "exe": "/usr/lib/jit",
        "anon": 1, "len": 4096})) for _ in range(5)]
    known = stream(norm, 6000, 6001, exe="/tmp/injector", writes=5, execs=5)
    unknown = stream(norm, 7000, 7001, exe="", writes=5, execs=5)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "A_jit_only": run("A_jit_only", jit_only),
        "B_untrusted_known": run("B_untrusted_known", known),
        "C_unknown_provenance": run("C_unknown_provenance", unknown),
        "rule_severities": {"LINUX-EXEC-CORR-109": "low",
                            "LINUX-EXEC-CORR-110": "high"},
    }
    report["checks"] = {
        "A_no_corr110_alert": all(a["rule"] != "LINUX-EXEC-CORR-110"
                                  for a in report["A_jit_only"]["alerts"]),
        "B_corr110_alerts": any(a["rule"] == "LINUX-EXEC-CORR-110"
                                for a in report["B_untrusted_known"]["alerts"]),
        "C_no_corr110_alert": all(a["rule"] != "LINUX-EXEC-CORR-110"
                                  for a in report["C_unknown_provenance"]["alerts"]),
        "C_write_still_detected": any(a["rule"] == "LINUX-INJECT-106"
                                      for a in report["C_unknown_provenance"]["alerts"]),
        "C_still_visible_as_signal": any(
            v["rule"] == "LINUX-EXEC-CORR-109"
            for v in report["C_unknown_provenance"]["verdicts"]),
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({k: report[k] for k in ("checks",)}, ensure_ascii=False))
    print("A alerts:", report["A_jit_only"]["alert_count"],
          "| B alerts:", report["B_untrusted_known"]["alert_count"],
          "| C alerts:", report["C_unknown_provenance"]["alert_count"])


if __name__ == "__main__":
    main()
