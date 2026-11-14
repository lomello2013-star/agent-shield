#!/usr/bin/env python3
"""Local STML demo server with a seeded fleet (visual review only).

    python scripts/stml_demo.py
    open http://127.0.0.1:18080/ui/#viewer=demo-viewer&admin=demo-admin&approver=demo-approver

Tokens are demo-only. The DB is recreated under artifacts/demo/.
"""
from __future__ import annotations

import pathlib
import shutil
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from stml.server.app import ServerConfig, start_server  # noqa: E402
from stml.server.store import Store  # noqa: E402

TENANT = "demo"
DB = HERE / "artifacts" / "demo" / "stml-demo.sqlite3"
URL = "http://127.0.0.1:18080/ui/#viewer=demo-viewer&admin=demo-admin&approver=demo-approver"

AGENTS = [
    ("prod-win-01", "windows", "x64", "healthy", "v12"),
    ("prod-linux-01", "linux", "x64", "healthy", "v12"),
    ("lab-linux-02", "linux", "x64", "degraded", "v11"),
    ("edge-win-02", "windows", "arm64", "offline", "v11"),
    ("tamper-win-03", "windows", "x64", "tamper", "v10"),
]


def main() -> int:
    DB.parent.mkdir(parents=True, exist_ok=True)
    if DB.exists():
        DB.unlink()
    store = Store(DB)
    for host, os_name, arch, status, policy in AGENTS:
        token = store.create_enrol_token(TENANT)
        agent_id = store.enrol(token, TENANT, host, os_name, arch, "1.0.0",
                               "demo-pubkey")
        store.heartbeat(agent_id, status, {"heartbeat": True, "queue": 0})
        store.inventory(agent_id, {"policy_version": policy})
        if status == "offline":
            with store._lock:  # demo only: make last_seen visibly old
                store._db.execute(
                    "UPDATE agents SET last_seen = ? WHERE id = ?",
                    (time.time() - 240, agent_id))
                store._db.commit()

    store.add_policy({
        "policy_id": "baseline", "version": "v12", "channel": "stable",
        "content": {"rules": 30, "prevention": True, "e7": "0.90136@1%"},
        "key_id": "demo-key", "signature": "demo", "tenant_id": TENANT,
    })
    store.add_policy({
        "policy_id": "baseline", "version": "v11", "channel": "stable",
        "content": {"rules": 28, "prevention": True},
        "key_id": "demo-key", "signature": "demo", "tenant_id": TENANT,
    })
    store.add_policy({
        "policy_id": "baseline", "version": "v13-rc", "channel": "canary",
        "content": {"rules": 31, "prevention": False},
        "key_id": "demo-key", "signature": "demo", "tenant_id": TENANT,
    })
    store.propose_approval("policy", "baseline@v13-rc",
                           {"diff": "rules: +1, prevention: off"}, "demo-admin", TENANT)
    store.propose_approval("key", "policy-key:rotate",
                           {"reason": "scheduled rotation"}, "demo-admin", TENANT)

    config = ServerConfig(
        tenant_id=TENANT, admin_token="demo-admin", viewer_token="demo-viewer",
        approver_token="demo-approver", require_approval=True, event_bus="local")
    server, _ = start_server(store, config, port=18080)
    print(f"demo server: {URL}", flush=True)
    print(f"db: {DB}", flush=True)
    print("tokens: viewer=demo-viewer admin=demo-admin approver=demo-approver",
          flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

