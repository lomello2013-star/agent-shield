"""Windows Defender/Operational as a second user-mode source (T1562 tampering).

The log is readable without elevation. 5007 (configuration changed) is the bulk of
the real records on this host; 5001/5010/5012 are protection-disabled events.
Writes artifacts/windows_defender.json.
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

OUT = os.path.join(HERE, "artifacts", "windows_defender.json")
LOG = "Microsoft-Windows-Windows Defender/Operational"
IDS = (5001, 5007, 5010, 5012, 1116, 1117)
HOST = HostContext(host_id="host-win", os="windows", version="10.0.19045", arch="x64")


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def main() -> None:
    cfg = DaemonConfig(sources=["win.eventlog"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 200},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_def_"), config=cfg, host=HOST,
               rules_path=os.path.join(HERE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()
    source = WindowsEventLogSource(log_name=LOG, event_ids=IDS, max_events=200)

    events = source.poll()
    second = source.poll()
    by_id: dict[int, int] = {}
    by_class: dict[str, int] = {}
    by_action: dict[str, int] = {}
    pipeline_lat = []
    verdicts = 0
    for record in events:
        by_id[record.event_id] = by_id.get(record.event_id, 0) + 1
        raw = record.to_raw()
        cls = raw["data"].get("classification", "n/a")
        by_class[cls] = by_class.get(cls, 0) + 1
        by_action[raw["action"]] = by_action.get(raw["action"], 0) + 1
        d.submit("win.eventlog", raw)
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
        "events_read": len(events), "second_poll_fresh": len(second),
        "by_event_id": {str(k): v for k, v in sorted(by_id.items())},
        "by_classification": by_class,
        "by_action": by_action,
        "verdicts_before_classification": len(events),
        "verdicts": verdicts, "rule_hits": rules,
        "poll_ms": round(source.last_query_ms, 3),
        "pipeline_ms_p50": round(statistics.median(pipeline_lat), 3) if pipeline_lat else None,
        "pipeline_ms_p95": p95(pipeline_lat),
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "real Defender log records, readable without elevation; 1116/1117 are "
                "detections (observe-only), 5001/5007/5010/5012 are tamper signals",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()


