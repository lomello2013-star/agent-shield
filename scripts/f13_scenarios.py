"""F13: labelled scenario harness for E1-E5 (E6 is unmeasurable without kernel visibility).

This is explicitly **a harness, not red-team**: scenarios are authored, mapped to the
ATT&CK techniques that are in scope, and measured end-to-end through the rule engine and
the policy gate. Detection = a verdict was produced; prevention = the gate produced a
containment action (reversible suspend/quarantine).

Writes artifacts/f13_scenarios.json.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "scripts"))

import f12_behavioral as harness  # noqa: E402  (reuses Clock + event builder)
from core.gate import AlertBudget, PolicyGate  # noqa: E402
from core.rules import RuleEngine, load_rules  # noqa: E402

OUT = os.path.join(HERE, "artifacts", "f13_scenarios.json")

EVIL = {"pid": 9000, "ppid": 1, "name": "evil", "path": r"C:\Temp\evil.exe",
        "cmdline_hash": "aa" * 32, "cmdline_redacted": "evil"}
LINUX_EVIL = {"pid": 9100, "ppid": 1, "name": "tool", "path": "/tmp/tool",
              "cmdline_hash": "bb" * 32, "cmdline_redacted": "tool"}


def scenarios() -> list[dict]:
    e = harness.event
    return [
        # ---- E1/E2: массовые (ransomware-поведение)
        {"id": "R1_mass_encrypt", "class": "E1_E2_mass", "technique": "T1486",
         "events": lambda: [e("file.write", "write", actor=EVIL,
                              obj={"type": "file", "path": rf"C:\data\f{i}.enc"})
                            for i in range(60)]},
        {"id": "R2_canary_delete", "class": "E1_E2_mass", "technique": "T1485",
         "events": lambda: [e("file.delete", "delete", actor=EVIL,
                              obj={"type": "file",
                                   "path": r"C:\ProgramData\canary\backup.dat"})]},
        # ---- E3/E4: целевые
        {"id": "T1_lsass", "class": "E3_E4_targeted", "technique": "T1003",
         "events": lambda: [e("process.access", "open_process", actor=EVIL,
                              obj={"type": "process", "path": r"lsass.exe"})]},
        {"id": "T2_cred_read", "class": "E3_E4_targeted", "technique": "T1003",
         "events": lambda: [e("file.read", "open", platform="linux", actor=LINUX_EVIL,
                              obj={"type": "file", "path": "/etc/shadow"})]},
        {"id": "T3_injection", "class": "E3_E4_targeted", "technique": "T1055",
         "events": lambda: [e("memory.access", "process_vm_writev", platform="linux",
                              actor=LINUX_EVIL,
                              obj={"type": "process", "path": "pid:7000"})]},
        {"id": "T4_service_persist", "class": "E3_E4_targeted", "technique": "T1543",
         "events": lambda: [e("persistence.change", "service_install", actor=EVIL,
                              obj={"type": "service", "path": "evilsvc"},
                              platform_data={"ServiceName": "evilsvc"})]},
        {"id": "T5_runkey", "class": "E3_E4_targeted", "technique": "T1547",
         "events": lambda: [e("registry.change", "key_write", actor=EVIL,
                              obj={"type": "registry",
                                   "path": r"HKCU\Software\Microsoft\Windows"
                                           r"\CurrentVersion\Run\evil"})]},
        # ---- E5: fileless / LOLBin
        {"id": "F1_ps_encoded", "class": "E5_fileless", "technique": "T1027",
         "events": lambda: [e("process.start", "start", actor={
             "pid": 9200, "ppid": 1, "name": "powershell.exe",
             "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "cmdline_hash": "cc" * 32,
             "cmdline_redacted": "powershell -enc SQBFAFgA"},
             platform_data={"cmdline": "powershell -enc SQBFAFgA"})]},
        {"id": "F2_tmp_exec", "class": "E5_fileless", "technique": "T1059",
         "events": lambda: [e("process.start", "start", platform="linux",
                              actor=LINUX_EVIL)]},
        {"id": "F3_wmi_subscription", "class": "E5_fileless", "technique": "T1546",
         "events": lambda: [e("persistence.change", "wmi_subscription", actor=EVIL,
                              obj={"type": "wmi", "path": "root\\subscription"})]},
    ]


def main() -> None:
    clock = harness.Clock()
    engine = RuleEngine(load_rules([os.path.join(HERE, "rules", "base.json")]),
                        now_fn=clock)
    gate = PolicyGate(budget=AlertBudget(per_window=100, window_s=86400, now_fn=clock))

    results = []
    for scenario in scenarios():
        detected = prevented = alerted = False
        rules_hit: list[str] = []
        for ev in scenario["events"]():
            clock.t += 0.05
            for verdict in engine.evaluate(ev):
                detected = True
                rules_hit.append(verdict.rule_id or "")
                decision = gate.decide(verdict, "f13-host")
                if decision.actions:
                    prevented = True
                if decision.alert:
                    alerted = True
        results.append({"scenario": scenario["id"], "class": scenario["class"],
                        "technique": scenario["technique"], "detected": detected,
                        "prevented": prevented, "alerted": alerted,
                        "rules": sorted(set(rules_hit))})

    classes: dict[str, dict] = {}
    for result in results:
        bucket = classes.setdefault(result["class"], {"total": 0, "detected": 0,
                                                      "prevented": 0, "alerted": 0})
        bucket["total"] += 1
        bucket["detected"] += int(result["detected"])
        bucket["prevented"] += int(result["prevented"])
        bucket["alerted"] += int(result["alerted"])
    for bucket in classes.values():
        bucket["detection_pct"] = round(100 * bucket["detected"] / bucket["total"], 1)
        bucket["prevention_pct"] = round(100 * bucket["prevented"] / bucket["total"], 1)

    report = {
        "harness": "labelled scenarios (NOT red-team)",
        "scenarios": len(results),
        "detected": sum(1 for r in results if r["detected"]),
        "prevented": sum(1 for r in results if r["prevented"]),
        "by_class": classes,
        "results": results,
        "e6_rootkit": {
            "status": "unmeasurable",
            "why": "requires kernel visibility (minifilter/ELAM or eBPF kernel hooks "
                   "beyond observation); blocked by signature/elevation (A/B/D)",
        },
        "note": "detection = verdict produced; prevention = gate produced a containment "
                "action (reversible). Harness scenarios are authored, so this is a "
                "regression suite, not an effectiveness proof",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({"scenarios": report["scenarios"], "detected": report["detected"],
                      "prevented": report["prevented"]}, ensure_ascii=False))
    for name, bucket in sorted(classes.items()):
        print(f"  {name}: detect {bucket['detection_pct']}% "
              f"prevent {bucket['prevention_pct']}% ({bucket['detected']}/{bucket['total']})")
    for result in results:
        if not result["detected"]:
            print(f"  MISSED: {result['scenario']}")


if __name__ == "__main__":
    main()
