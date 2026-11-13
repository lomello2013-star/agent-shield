"""Report the state of the long supervised soak without disturbing it.

Reads the partial artifact (written every 60 s by scripts/soak_supervised.py), the final
report when it exists, the restart log and the interpreter version. Prints one compact
block so a later session can pick the run up.

Usage: python scripts/soak_progress.py [--json]
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTIAL = os.path.join(HERE, "artifacts", "soak_supervised_partial.json")
FINAL = os.path.join(HERE, "artifacts", "soak_supervised.json")
EVENTS = os.path.join(HERE, "artifacts", "_stdout", "soak_supervised_events.jsonl")


def load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def main() -> int:
    partial = load(PARTIAL)
    final = load(FINAL)
    events = 0
    if os.path.exists(EVENTS):
        with open(EVENTS, encoding="utf-8", errors="replace") as fh:
            events = sum(1 for line in fh if line.strip())
    snapshot = {
        "partial_window_s": partial.get("window_s"),
        "partial_restarts": partial.get("restarts"),
        "partial_availability_pct": partial.get("availability_pct"),
        "partial_downtime_s": partial.get("downtime_total_s"),
        "final": {k: final.get(k) for k in ("window_s", "python", "restarts",
                                           "availability_pct", "downtime_total_s",
                                           "audit_chain", "lifecycle")} if final else None,
        "restart_events_logged": events,
    }
    if "--json" in sys.argv:
        print(json.dumps(snapshot, ensure_ascii=False))
        return 0
    print(f"partial: window={snapshot['partial_window_s']}s "
          f"restarts={snapshot['partial_restarts']} "
          f"availability={snapshot['partial_availability_pct']}% "
          f"downtime={snapshot['partial_downtime_s']}s")
    if snapshot["final"]:
        f = snapshot["final"]
        print(f"final:   window={f['window_s']}s python={f['python']} restarts={f['restarts']} "
              f"availability={f['availability_pct']}% downtime={f['downtime_total_s']}s "
              f"chain={f['audit_chain']}")
    else:
        print("final:   not written yet (run still in progress)")
    print(f"restart events in log: {snapshot['restart_events_logged']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
