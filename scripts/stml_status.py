"""Read-only status of the STML server and the local connector (no writes, no locks)."""

from __future__ import annotations

import json
import os
import sqlite3

DB = r"C:\ProgramData\AIDefender\stml\server.sqlite3"
LOG = r"C:\ProgramData\AIDefender\stml\connector.log"


def main() -> int:
    if os.path.exists(DB):
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
        cur = con.cursor()
        tables = [row[0] for row in cur.execute(
            "select name from sqlite_master where type='table' order by name")]
        print("server db tables:", ", ".join(tables))
        for table in tables:
            try:
                count = cur.execute(f"select count(*) from {table}").fetchone()[0]
            except sqlite3.Error as exc:
                count = f"error: {exc}"
            print(f"  {table}: {count}")
        con.close()
    else:
        print("server db not found")
    if os.path.exists(LOG):
        with open(LOG, encoding="utf-8", errors="replace") as fh:
            lines = [line for line in fh if line.strip()]
        print("connector log lines:", len(lines))
        if lines:
            try:
                last = json.loads(lines[-1])
                health = last.get("heartbeat", {}).get("health", {})
                print("last heartbeat:", last.get("heartbeat", {}).get("sent_at"))
                print("  server:", last.get("server"), "enrolled:", last.get("enrolled"),
                      "isolated:", last.get("isolated"))
                print("  status:", health.get("status"), "uptime_s:", health.get("uptime_s"))
                print("  ingest:", health.get("ingest", {}).get("received"),
                      "delivered:", health.get("ingest", {}).get("delivered"),
                      "lost:", health.get("ingest", {}).get("lost"))
                print("  verdicts:", health.get("verdicts"), "alerts:", health.get("alerts"),
                      "containments:", health.get("containments"))
                print("  last_error:", last.get("last_error"))
            except (json.JSONDecodeError, AttributeError) as exc:
                print("cannot parse last heartbeat:", exc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
