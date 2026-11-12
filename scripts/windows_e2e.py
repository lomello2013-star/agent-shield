"""Windows end-to-end without elevation: real System-log events -> aidfd -> verdicts.

Uses event 7045 (service installed), which a normal user can read. No service is
created by this script (that needs admin) — it consumes the real historical records
already present on the host and proves the source->rule->verdict path.

Writes artifacts/windows_e2e.json.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402
from core.winsource import WindowsEventLogSource  # noqa: E402

OUT = os.path.join(HERE, "artifacts", "windows_e2e.json")
HOST = HostContext(host_id="host-win", os="windows", version="10.0.19045", arch="x64")


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def main() -> None:
    cfg = DaemonConfig(sources=["win.eventlog"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 100},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_win_"), config=cfg, host=HOST,
               rules_path=os.path.join(HERE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()
    source = WindowsEventLogSource(log_name="System", event_ids=(7045, 7040, 1102),
                                   max_events=60)

    poll1 = source.poll()
    poll2 = source.poll()          # bookmark: must return nothing new
    pipeline_lat = []
    verdicts = 0
    for record in poll1:
        d.submit("win.eventlog", record.to_raw())
        t0 = time.perf_counter()
        produced = d.tick()
        pipeline_lat.append((time.perf_counter() - t0) * 1000)
        verdicts += produced["verdicts"]
    while d.pipeline.ingest.backlog_events() > 0:
        produced = d.tick()
        verdicts += produced["verdicts"]
    health = d.health()
    rules = d.engine.counts()
    d.stop()

    report = {
        "environment": {"python": sys.version.split()[0], "platform": sys.platform},
        "log": source.stats(),
        "events_read": len(poll1),
        "second_poll_fresh": len(poll2),
        "event_ids": sorted({r.event_id for r in poll1}),
        "verdicts": verdicts,
        "rule_hits": rules,
        "poll_ms": round(source.last_query_ms, 3),
        "pipeline_ms_p50": round(statistics.median(pipeline_lat), 3) if pipeline_lat else None,
        "pipeline_ms_p95": p95(pipeline_lat),
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "real System-log records readable without elevation; no service was "
                "created by this script",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
