"""Count *actual* inventory-409 occurrences in the connector log (the field is sticky)."""

from __future__ import annotations

import json

LOG = r"C:\ProgramData\AIDefender\stml\connector.log"

prev = None
transitions = 0
first_at = None
last_at = None
seq = []
with open(LOG, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        err = record.get("last_error") or ""
        kind = "replayed" if "replayed nonce" in err else (err.split(":")[0] if err else "ok")
        when = record.get("heartbeat", {}).get("sent_at", "")
        if kind == "replayed" and prev != "replayed":
            transitions += 1
            if first_at is None:
                first_at = when
            last_at = when
        seq.append(kind)
        prev = kind

print("records:", len(seq))
print("409 appearances (transitions into the state):", transitions)
print("first 409 at:", first_at)
print("last 409 at:", last_at)
print("current state:", seq[-1])
print("states seen:", sorted(set(seq)))
