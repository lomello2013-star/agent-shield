"""Rust load probe: 1000 enrolments + signed heartbeats, p95."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stml.connector.signing import generate_keypair, load_private, sign
from stml.contracts.v0 import AgentStatus, Heartbeat

N = 1000


def post(url: str, path: str, payload: dict, signature: str = "") -> dict:
    raw = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if signature:
        headers["X-STML-Signature"] = signature
    req = Request(url.rstrip("/") + path, data=raw, method="POST", headers=headers)
    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18102")
    ap.add_argument("--out", default="artifacts/stml_rust_load.json")
    args = ap.parse_args()
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="stml-rust-load-"))
    priv, pub = tmp / "agent.pem", tmp / "agent.pub"
    generate_keypair(priv, pub)
    pubkey = pub.read_text(encoding="utf-8")
    started = time.perf_counter()
    agents = []
    for i in range(N):
        body = post(args.url, "/v0/enrol", {
            "tenant_id": "t", "enrolment_token": f"load-{i}", "hostname": f"h{i}",
            "os": "windows", "arch": "x64", "agent_version": "0.1.0", "pubkey": pubkey})
        agents.append(body["agent_id"])
    enrol_s = time.perf_counter() - started

    def beat(agent_id: str) -> float:
        hb = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                       message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                       status=AgentStatus.HEALTHY)
        payload = hb.model_dump(mode="json")
        raw = json.dumps(payload).encode()
        t0 = time.perf_counter()
        post(args.url, "/v0/heartbeat", payload, sign(load_private(priv), raw))
        return time.perf_counter() - t0

    with ThreadPoolExecutor(max_workers=50) as pool:
        latencies = sorted(pool.map(beat, agents))
    p50 = latencies[len(latencies) // 2] * 1000
    p95 = latencies[int(len(latencies) * 0.95) - 1] * 1000
    report = {"agents": N, "enrol_s": round(enrol_s, 2),
              "heartbeat_p50_ms": round(p50, 1),
              "heartbeat_p95_ms": round(p95, 1),
              "passed_p95_under_2s": p95 < 2000}
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["passed_p95_under_2s"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
