"""S5 load probe: 1000 agents, enrolment + signed heartbeats, p95."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from stml.connector.signing import generate_keypair, load_private, sign
from stml.contracts.v0 import AgentStatus, Heartbeat
from stml.server.app import ServerConfig, start_server
from stml.server.store import Store

N = 1000
OUT = Path("artifacts/stml_s5_load.json")


def post(port: int, path: str, payload: dict, signature: str = "") -> dict:
    raw = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if signature:
        headers["X-STML-Signature"] = signature
    req = Request(f"http://127.0.0.1:{port}{path}", data=raw, method="POST", headers=headers)
    with urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="stml-s5-"))
    store = Store(tmp / "db.sqlite3")
    server, _ = start_server(store, ServerConfig(tenant_id="t", admin_token="a",
                                                viewer_token="v"), port=0)
    port = server.server_address[1]
    priv, pub = tmp / "agent.pem", tmp / "agent.pub"
    generate_keypair(priv, pub)
    pubkey = pub.read_text(encoding="utf-8")
    t0 = time.perf_counter()
    agents = []
    for i in range(N):
        token = store.create_enrol_token("t")
        body = post(port, "/v0/enrol", {
            "tenant_id": "t", "enrolment_token": token, "hostname": f"h{i}",
            "os": "windows", "arch": "x64", "agent_version": "0.1.0", "pubkey": pubkey,
        })
        agents.append(body["agent_id"])
    enrol_s = time.perf_counter() - t0

    def beat(agent_id: str) -> float:
        hb = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                       message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                       status=AgentStatus.HEALTHY)
        payload = hb.model_dump(mode="json")
        raw = json.dumps(payload).encode()
        started = time.perf_counter()
        post(port, "/v0/heartbeat", payload, sign(load_private(priv), raw))
        return time.perf_counter() - started

    with ThreadPoolExecutor(max_workers=50) as pool:
        latencies = sorted(pool.map(beat, agents))
    p95 = latencies[int(len(latencies) * 0.95) - 1]
    report = {"agents": N, "enrol_s": round(enrol_s, 2),
              "heartbeat_p50_ms": round(latencies[len(latencies) // 2] * 1000, 1),
              "heartbeat_p95_ms": round(p95 * 1000, 1),
              "passed_p95_under_2s": p95 < 2.0}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    server.shutdown()
    server.server_close()
    store.close()


if __name__ == "__main__":
    main()
