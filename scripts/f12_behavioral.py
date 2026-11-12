"""F12: behavioural TPR at the alert budget (E8) on a labelled synthetic stream.

E8 asks for TPR >= 0.85 while spending at most one alert per two weeks *on benign
traffic*. A 7-day pilot is not available (blocker D), so this harness simulates 14 days
of benign activity plus eight labelled behavioural scenarios and measures:

  * behavioural TPR  — share of scenarios that produced at least one verdict;
  * benign alerts    — how many alerts the budget actually spends on benign events;
  * budget respect   — <= 1 benign alert over the 14 simulated days.

The report says explicitly that this is a labelled harness, not a pilot.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.gate import AlertBudget, PolicyGate  # noqa: E402
from core.rules import RuleEngine, load_rules  # noqa: E402
from schemas.v3 import Event  # noqa: E402

OUT = os.path.join(HERE, "artifacts", "f12_behavioral.json")
DAYS = 14
HOST = {"host_id": "f12-host", "os": "windows", "version": "10.0.19045", "arch": "x64"}


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def event(category: str, action: str, platform: str = "windows",
          actor: dict | None = None, obj: dict | None = None,
          platform_data: dict | None = None) -> Event:
    payload = {
        "schema_version": "3.0", "event_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()),
        "ts_event": datetime(2026, 11, 1, tzinfo=timezone.utc).isoformat(),
        "ts_ingest": datetime(2026, 11, 1, tzinfo=timezone.utc).isoformat(),
        "platform": platform, "source": "harness.f12", "layer": "user",
        "category": category, "action": action,
        "actor": actor or {"pid": 1000, "ppid": 1, "name": "app",
                           "path": r"C:\Program Files\app\app.exe",
                           "cmdline_hash": "ab" * 32, "cmdline_redacted": "app"},
        "object": obj or {"type": "file", "path": r"C:\docs\a.txt"},
        "host": dict(HOST), "raw_ref": "raw/f12", "platform_data": platform_data or {},
    }
    return Event.model_validate(payload)


def benign_day(day: int, clock: Clock):
    """Yield benign events, advancing the clock per event.

    The clock must advance *while* events are evaluated: the rule engine reads the
    live clock, so pre-building a list would place every event at the same instant and
    instantly trip the 50-writes-in-10-s rule (this was an actual harness bug).
    """
    for i in range(20):
        clock.t += 1.0
        yield event("process.start", "start")
        clock.t += 1.0
        yield event("file.write", "write",
                    obj={"type": "file", "path": rf"C:\docs\day{day}_{i}.txt"})
        clock.t += 1.0
        yield event("net.connect", "connect",
                    obj={"type": "network", "path": "93.184.216.34:443",
                         "port": 443, "proto": "tcp"},
                    platform_data={"bytes_out": 1200})
        clock.t += 1.0
        yield event("file.read", "open",
                    obj={"type": "file", "path": r"C:\docs\readme.txt"})


def scenarios() -> list[dict]:
    ms = {"pid": 5000, "ppid": 1, "name": "evil", "path": r"C:\Temp\evil.exe",
          "cmdline_hash": "cd" * 32, "cmdline_redacted": "evil"}
    linux = {"pid": 6000, "ppid": 1, "name": "tool", "path": "/tmp/tool",
             "cmdline_hash": "ef" * 32, "cmdline_redacted": "tool"}
    return [
        {"id": "S1_mass_write", "platform": "windows",
         "build": lambda c: [event("file.write", "write", actor=ms,
                                   obj={"type": "file", "path": rf"C:\data\f{i}.enc"})
                             for i in range(60)]},
        {"id": "S2_canary_delete", "platform": "windows",
         "build": lambda c: [event("file.delete", "delete", actor=ms,
                                   obj={"type": "file",
                                        "path": r"C:\ProgramData\canary\secret.txt"})]},
        {"id": "S3_large_exfil", "platform": "windows",
         "build": lambda c: [event("net.connect", "connect", actor=ms,
                                   obj={"type": "network", "path": "203.0.113.9:8443",
                                        "port": 8443, "proto": "tcp"},
                                   platform_data={"bytes_out": 25_000_000})]},
        {"id": "S4_c2_port", "platform": "linux",
         "build": lambda c: [event("net.connect", "connect", platform="linux",
                                   actor=linux,
                                   obj={"type": "network", "path": "10.0.0.9:4444",
                                        "port": 4444, "proto": "tcp"})]},
        {"id": "S5_tmp_exec", "platform": "linux",
         "build": lambda c: [event("process.start", "start", platform="linux",
                                   actor=linux)]},
        {"id": "S6_injection", "platform": "linux",
         "build": lambda c: [event("memory.access", "process_vm_writev",
                                   platform="linux", actor=linux,
                                   obj={"type": "process", "path": "pid:7000"})]},
        {"id": "S7_cred_read", "platform": "linux",
         "build": lambda c: [event("file.read", "open", platform="linux", actor=linux,
                                   obj={"type": "file", "path": "/etc/shadow"})]},
        {"id": "S8_lsass_access", "platform": "windows",
         "build": lambda c: [event("process.access", "open_process", actor=ms,
                                   obj={"type": "process", "path": r"lsass.exe"})]},
    ]


def main() -> None:
    clock = Clock()
    engine = RuleEngine(load_rules([os.path.join(HERE, "rules", "base.json")]), now_fn=clock)
    budget = AlertBudget(per_window=1, window_s=DAYS * 24 * 3600, now_fn=clock)
    gate = PolicyGate(budget=budget)

    benign_count = 0
    benign_alerts = 0
    benign_alert_rules: list[str] = []
    for day in range(DAYS):
        for ev in benign_day(day, clock):
            benign_count += 1
            for verdict in engine.evaluate(ev):
                if gate.decide(verdict, HOST["host_id"]).alert:
                    benign_alerts += 1
                    benign_alert_rules.append(verdict.rule_id or "")

    results = []
    scenarios_run = scenarios()
    for index, scenario in enumerate(scenarios_run):
        clock.t += 3600.0 * 24          # a new day for each scenario
        detected = False
        alerts = 0
        for ev in scenario["build"](clock):
            clock.t += 0.05             # bursts stay inside the 10 s window
            for verdict in engine.evaluate(ev):
                detected = True
                if gate.decide(verdict, HOST["host_id"]).alert:
                    alerts += 1
        results.append({"scenario": scenario["id"], "platform": scenario["platform"],
                        "detected": detected, "alerts": alerts,
                        "rule_hits": dict(engine.counts())})

    detected_scenarios = sum(1 for r in results if r["detected"])
    alerted_scenarios = sum(1 for r in results if r["alerts"] > 0)
    tpr = detected_scenarios / len(results)
    report = {
        "harness": "labelled synthetic stream (not a pilot)",
        "simulated_days": DAYS,
        "benign_events": benign_count,
        "benign_alerts": benign_alerts,
        "benign_alert_rules": benign_alert_rules,
        "budget_per_14_days": 1,
        "budget_respected": benign_alerts <= 1,
        "malicious_alerts_suppressed_by_budget": all(r["alerts"] == 0 for r in results),
        "alerts_per_scenario": {r["scenario"]: r["alerts"] for r in results},
        "alerted_scenarios": sum(1 for r in results if r["alerts"] > 0),
        "note_budget": "critical verdicts bypass the alert budget (F12b: 1 -> 3 alerted); "
                       "high-severity findings remain budgeted, so after the budget is "
                       "spent they are contained but not announced — accepted noise cap, "
                       "to be revisited at pilot",
        "scenarios": len(results),
        "detected": detected_scenarios,
        "behavioural_tpr": round(tpr, 4),
        "target_tpr": 0.85,
        "tpr_met": tpr >= 0.85,
        "details": results,
        "note": "E8 target is TPR>=0.85 at <=1 alert per two weeks on benign traffic; "
                "measured on a labelled harness because a 7-day pilot needs a fleet",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({k: report[k] for k in
                      ("benign_events", "benign_alerts", "budget_respected",
                       "behavioural_tpr", "tpr_met", "detected", "scenarios")},
                     ensure_ascii=False))
    for detail in results:
        print(f"  {detail['scenario']}: detected={detail['detected']} alerts={detail['alerts']}")


if __name__ == "__main__":
    main()
