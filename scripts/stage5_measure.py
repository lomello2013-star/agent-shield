"""Stage 5 measurement: rules engine throughput, rule coverage, ATT&CK matrix.

Writes docs/coverage-matrix.md (generated, not hand-edited) and
artifacts/stage5_report.json. Scenario detection is a *smoke* check on authored
fixtures вЂ” real effectiveness needs red-team (stage 12), stated in the report.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.coverage import build_matrix, load_techniques, summarize, write_matrix
from core.rules import RuleEngine, lint_rules, load_rules
from schemas.v3 import Event

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
REPORT = os.path.join(HERE, "artifacts", "stage5_report.json")
MATRIX_MD = os.path.join(HERE, "docs", "coverage-matrix.md")


def event(category="process.start", action="start", actor_path=r"C:\Windows\System32\notepad.exe",
          actor_name="notepad.exe", object_path=r"C:\Users\public\doc.txt", object_port=None,
          platform_data=None):
    return Event.model_validate({
        "schema_version": "3.0", "event_id": str(uuid.uuid4()), "trace_id": str(uuid.uuid4()),
        "ts_event": NOW.isoformat(), "ts_ingest": NOW.isoformat(),
        "platform": "windows", "source": "win.etw.ti", "layer": "kernel",
        "category": category, "action": action,
        "actor": {"pid": 100, "name": actor_name, "path": actor_path,
                  "cmdline_hash": "ab" * 32, "cmdline_redacted": actor_name},
        "object": {"type": "file", "path": object_path, "port": object_port},
        "host": {"host_id": "host-1", "os": "windows", "version": "10.0.19045", "arch": "x64"},
        "raw_ref": "raw/x.jsonl.zst#1",
        "platform_data": platform_data or {},
    })


def corpus(n: int = 20_000) -> list[Event]:
    """80% benign, 20% attack-ish; deterministic mix."""
    out = []
    for i in range(n):
        if i % 5 == 0:
            out.append(event(category="process.start",
                             actor_path=r"C:\Users\u\AppData\Local\Temp\drop.exe",
                             actor_name="drop.exe"))
        elif i % 5 == 1:
            out.append(event(category="registry.change", action="set_value",
                             object_path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x"))
        elif i % 5 == 2:
            out.append(event(category="net.connect", action="connect",
                             object_path="10.0.0.5:445", object_port=445))
        else:
            out.append(event())
    return out


def main() -> None:
    rules = load_rules([os.path.join(HERE, "rules", "base.json")])
    techniques = load_techniques(os.path.join(HERE, "rules", "techniques.json"))
    problems = lint_rules(rules, known_techniques={t.id for t in techniques})
    engine = RuleEngine(rules)

    rows = build_matrix(techniques, rules)
    summary = summarize(rows)
    write_matrix(MATRIX_MD, rows, summary)

    # smoke detection on authored fixtures (not a holdout)
    fixtures = {
        "WIN-EXEC-TEMP-001": event(actor_path=r"C:\Temp\x.exe", actor_name="x.exe"),
        "WIN-LSASS-ACCESS-004": event(category="process.access", action="open_process",
                                      object_path=r"C:\Windows\System32\lsass.exe"),
        "NET-SMB-LATERAL-012": event(category="net.connect", action="connect",
                                     object_path="10.0.0.5:445", object_port=445),
        "WIN-RUNKEY-005": event(category="registry.change", action="set_value",
                                object_path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x"),
        "WIN-LOG-CLEAR-008": event(category="log.tamper", action="clear"),
    }
    smoke = {}
    for rid, ev in fixtures.items():
        verdicts = engine.evaluate(ev)
        smoke[rid] = [v.rule_id for v in verdicts]

    # throughput / latency on the mixed corpus
    events = corpus(20_000)
    latencies = []
    hits = 0
    t0 = time.perf_counter()
    for ev in events:
        t = time.perf_counter()
        verdicts = engine.evaluate(ev)
        latencies.append((time.perf_counter() - t) * 1000.0)   # ms
        hits += len(verdicts)
    elapsed = time.perf_counter() - t0
    latencies.sort()

    report = {
        "rules": len(rules),
        "lint_problems": problems,
        "coverage": summary,
        "smoke_detections": smoke,
        "throughput": {
            "events": len(events),
            "elapsed_s": round(elapsed, 3),
            "events_per_s": round(len(events) / elapsed, 0),
            "verdicts": hits,
            "latency_ms_p50": round(latencies[len(latencies) // 2], 4),
            "latency_ms_p95": round(latencies[int(len(latencies) * 0.95)], 4),
            "latency_ms_p99": round(latencies[int(len(latencies) * 0.99)], 4),
            "latency_ms_max": round(latencies[-1], 4),
            "budget_ms": 5.0,
            "within_fast_budget": latencies[int(len(latencies) * 0.99)] < 5.0,
        },
        "matrix_markdown": MATRIX_MD,
        "environment": {"python": sys.version.split()[0], "cpu": os.cpu_count()},
        "note": "scenario detection is authored-fixture smoke, not a holdout; "
                "E11 real validation requires red-team (stage 12)",
    }
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

