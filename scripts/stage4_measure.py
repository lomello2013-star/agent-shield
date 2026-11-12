"""Stage 4 measurement: normalization cost per source, end-to-end pipeline, priority order.

Writes artifacts/stage4_report.json.
"""

from __future__ import annotations

import json
import os
import random
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ingest import IngestPipeline
from core.normalize import HostContext, Normalizer
from core.pipeline import Pipeline, priority_for
from core.rules import RuleEngine, load_rules

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "artifacts", "stage4_report.json")
RULES = load_rules([os.path.join(HERE, "rules", "base.json")])
HOST = HostContext(host_id="host-1", os="windows", version="10.0.19045", arch="x64")


def etw(i: int) -> dict:
    return {
        "process_id": 1000 + i, "parent_id": 4,
        "process_name": r"C:\Temp\sample.exe" if i % 10 == 0 else r"C:\Windows\System32\notepad.exe",
        "cmdline": f"sample.exe --run {i}",
        "target": r"C:\Windows\System32\lsass.exe" if i % 10 == 0 else r"C:\Users\public\f.txt",
        "category": "process.access" if i % 10 == 0 else "file.write",
        "action": "open_process" if i % 10 == 0 else "write",
    }


def amsi(i: int) -> dict:
    return {"app_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "content_name": f"ScriptBlock-{i}", "result": 1, "process_id": 2000 + i}


def ebpf(i: int) -> dict:
    return {"pid": 3000 + i, "ppid": 1, "comm": "bash", "exe": "/usr/bin/bash",
            "syscall": "execve" if i % 2 else "openat", "filename": f"/tmp/f{i}"}


def auditd(i: int) -> dict:
    return {"exe": "/bin/sh", "pid": 4000 + i, "key": "exec" if i % 2 else "open",
            "path": f"/tmp/a{i}"}


SOURCES = {"win.etw.ti": etw, "win.amsi": amsi, "linux.ebpf": ebpf, "linux.auditd": auditd}


def measure_normalization(n: int = 5000) -> dict:
    out = {}
    for source, gen in SOURCES.items():
        norm = Normalizer(host=HOST)
        lat = []
        t0 = time.perf_counter()
        for i in range(n):
            t = time.perf_counter()
            norm.normalize(source, gen(i))
            lat.append((time.perf_counter() - t) * 1_000_000)   # µs
        elapsed = time.perf_counter() - t0
        lat.sort()
        out[source] = {
            "records": n,
            "per_s": round(n / elapsed, 0),
            "p50_us": round(lat[len(lat) // 2], 1),
            "p95_us": round(lat[int(len(lat) * 0.95)], 1),
            "max_us": round(lat[-1], 1),
            "quarantined": norm.stats()["quarantined"],
        }
    return out


def measure_end_to_end(total: int = 20000) -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_s4_")
    pipe = Pipeline(
        normalizer=Normalizer(host=HOST, quarantine_path=os.path.join(tmp, "q.jsonl")),
        ingest=IngestPipeline(capacity=5000, reserved_ratio=0.2,
                              spill_path=os.path.join(tmp, "spool.jsonl")),
        engine=RuleEngine(RULES),
    )
    t0 = time.perf_counter()
    for i in range(total):
        source = ["win.etw.ti", "win.amsi", "linux.ebpf", "linux.auditd"][i % 4]
        pipe.submit_raw(source, SOURCES[source](i))
        if i % 200 == 0:
            pipe.run_once(500)
    while True:
        chunk = pipe.run_once(1000)
        if not chunk and pipe.ingest.backlog_events() == 0:
            break
    elapsed = time.perf_counter() - t0
    stats = pipe.stats()
    return {
        "records": total, "elapsed_s": round(elapsed, 2),
        "records_per_s": round(total / elapsed, 0),
        "verdicts": stats["verdicts"], "rejected": stats["rejected"],
        "lost": stats["ingest"]["lost"], "ledger_ok": pipe.ingest.ledger_ok(),
        "spilled_pending": stats["ingest"]["spilled_pending"],
        "quarantined": stats["normalizer"]["quarantined"],
        "loss_ratio_pct": round(100 * stats["ingest"]["lost"] / total, 6),
        "target_loss_pct": 0.01,
    }


def measure_quarantine() -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_s4q_")
    path = os.path.join(tmp, "q.jsonl")
    norm = Normalizer(host=HOST, quarantine_path=path)
    bad = [{"process_id": 1}, {"process_name": r"C:\a.exe"}, {"process_id": "x",
                                                              "process_name": r"C:\a.exe"}]
    for i in range(200):
        norm.normalize_or_quarantine("win.etw.ti", bad[i % len(bad)])
    lines = 0
    with open(path, encoding="utf-8") as fh:
        lines = sum(1 for _ in fh)
    return {"malformed": 200, "quarantined": norm.stats()["quarantined"],
            "quarantine_lines": lines, "lost_silently": 0}


def measure_priority() -> dict:
    pipe = Pipeline(
        normalizer=Normalizer(host=HOST),
        ingest=IngestPipeline(capacity=10000, reserved_ratio=0.2),
        engine=RuleEngine(RULES),
    )
    for i in range(5000):
        pipe.submit_raw("win.amsi", {"app_name": r"C:\ps.exe", "content_name": f"sb{i}",
                                     "result": 1, "process_id": i})   # auth-noise? amsi=P1
    for i in range(50):
        pipe.submit_raw("win.etw.ti", {"process_id": 90000 + i, "parent_id": 4,
                                       "process_name": r"C:\Temp\x.exe",
                                       "target": r"C:\Windows\System32\lsass.exe",
                                       "category": "process.access",
                                       "action": "open_process"})
    first = pipe.ingest.drain(60)
    priorities = [priority_for(r.payload["category"]) for r in first]
    p0_before_noise = priorities.index(max(priorities)) if max(priorities) in priorities else -1
    return {
        "noise_submitted": 5000, "p0_submitted": 50,
        "first_60_priorities": {"p0": priorities.count(0), "p1": priorities.count(1),
                                "p2": priorities.count(2)},
        "all_p0_delivered_first": priorities[:50].count(0) == 50,
    }


def main() -> None:
    report = {
        "environment": {"python": sys.version.split()[0], "cpu": os.cpu_count()},
        "normalization": measure_normalization(),
        "end_to_end": measure_end_to_end(),
        "quarantine": measure_quarantine(),
        "priority": measure_priority(),
        "note": "synthetic records shaped like real provider payloads; not a live "
                "ETW/auditd capture (elevation blocker D)",
    }
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
