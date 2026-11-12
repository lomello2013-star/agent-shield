"""Audit-log benchmarks: fsync-per-record vs batched, full vs incremental verify.

Writes artifacts/audit_bench.json.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.selfprotect import HashChainLog

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "artifacts", "audit_bench.json")


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def bench_append(n: int, fsync_every: int) -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_bench_")
    log = HashChainLog(os.path.join(tmp, "log.jsonl"),
                       anchor_path=os.path.join(tmp, "anchor.json"),
                       fsync_every=fsync_every)
    lat = []
    t0 = time.perf_counter()
    for i in range(n):
        t = time.perf_counter()
        log.append("probe", {"i": i, "pad": "x" * 64})
        lat.append((time.perf_counter() - t) * 1000)
    log.flush()
    total = time.perf_counter() - t0
    return {"records": n, "fsync_every": fsync_every,
            "append_ms_p50": round(statistics.median(lat), 4),
            "append_ms_p95": p95(lat),
            "records_per_s": round(n / total, 0),
            "total_s": round(total, 2),
            "file_kb": round(os.path.getsize(log.path) / 1024, 1)}


def bench_verify(n: int = 20000) -> dict:
    tmp = tempfile.mkdtemp(prefix="aidf_benchv_")
    log = HashChainLog(os.path.join(tmp, "log.jsonl"),
                       anchor_path=os.path.join(tmp, "anchor.json"), fsync_every=256)
    for i in range(n):
        log.append("probe", {"i": i})
    log.flush()

    t0 = time.perf_counter()
    full = log.verify(incremental=False)
    full_ms = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    inc = log.verify(incremental=True)
    inc_idle_ms = (time.perf_counter() - t0) * 1000

    for i in range(100):
        log.append("probe", {"i": n + i})
    t0 = time.perf_counter()
    inc2 = log.verify(incremental=True)
    inc_tail_ms = (time.perf_counter() - t0) * 1000

    return {"records": n, "full_verify_ms": round(full_ms, 3),
            "incremental_idle_ms": round(inc_idle_ms, 4),
            "incremental_100_new_ms": round(inc_tail_ms, 4),
            "full_ok": full.ok, "incremental_ok": inc2.ok,
            "speedup_idle_x": round(full_ms / max(0.0001, inc_idle_ms), 1)}


def main() -> None:
    report = {
        "append": [bench_append(2000, 1), bench_append(20000, 64), bench_append(20000, 256)],
        "verify": bench_verify(),
        "note": "fsync_every>1 trades durability of up to N-1 tail records for throughput; "
                "the chain stays valid because unacknowledged records are not sealed",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
