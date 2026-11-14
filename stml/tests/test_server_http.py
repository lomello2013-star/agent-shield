import json
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from stml.connector.signing import generate_keypair, load_private, sign
from stml.contracts.v0 import AgentStatus, Heartbeat, Priority, Report
from stml.server.app import ServerConfig, start_server
from stml.server.store import Store


def _request(port: int, method: str, path: str, payload=None, token: str = "",
             signature: str = "") -> tuple[int, dict]:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if signature:
        headers["X-STML-Signature"] = signature
    req = Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=headers)
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def _setup(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    config = ServerConfig(tenant_id="t", admin_token="admin", viewer_token="viewer",
                          approver_token="approver")
    server, _ = start_server(store, config, port=0)
    port = server.server_address[1]
    token = store.create_enrol_token("t")
    priv, pub = tmp_path / "key.pem", tmp_path / "key.pub"
    generate_keypair(priv, pub)
    code, body = _request(port, "POST", "/v0/enrol", {
        "tenant_id": "t", "enrolment_token": token, "hostname": "h1",
        "os": "windows", "arch": "x64", "agent_version": "0.1.0",
        "pubkey": pub.read_text(encoding="utf-8"),
    })
    assert code == 201, body
    return store, server, port, body["agent_id"], priv


def _signed(priv, payload: dict) -> tuple[bytes, str]:
    raw = json.dumps(payload).encode()
    return raw, sign(load_private(priv), raw)


def test_health_dashboard_and_enrol(tmp_path):
    store, server, port, agent_id, _ = _setup(tmp_path)
    try:
        assert _request(port, "GET", "/health")[0] == 200
        with urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
            assert "STML Console" in resp.read().decode()
        with urlopen(f"http://127.0.0.1:{port}/ui/", timeout=5) as resp:
            assert "Approvals" in resp.read().decode()
        code, body = _request(port, "GET", "/v0/agents", token="viewer")
        assert code == 200 and len(body["agents"]) == 1
        assert body["agents"][0]["id"] == agent_id
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_signed_heartbeat_replay_and_isolate(tmp_path):
    store, server, port, agent_id, priv = _setup(tmp_path)
    try:
        hb = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                       message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                       status=AgentStatus.HEALTHY, health={"ok": True})
        payload = hb.model_dump(mode="json")
        raw, sig = _signed(priv, payload)
        code, body = _request(port, "POST", "/v0/heartbeat", payload, signature=sig)
        assert code == 200 and body["isolated"] is False, body

        # same nonce -> replay rejected
        code, _ = _request(port, "POST", "/v0/heartbeat", payload, signature=sig)
        assert code == 409

        code, _ = _request(port, "POST", f"/v0/agents/{agent_id}/isolate",
                           {"isolated": True}, token="admin")
        assert code == 200
        hb2 = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                        message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                        status=AgentStatus.HEALTHY)
        p2 = hb2.model_dump(mode="json")
        _, sig2 = _signed(priv, p2)
        code, body = _request(port, "POST", "/v0/heartbeat", p2, signature=sig2)
        assert code == 200 and body["isolated"] is True
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_command_delivery_and_ack(tmp_path):
    store, server, port, agent_id, priv = _setup(tmp_path)
    try:
        hb = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                       message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                       status=AgentStatus.HEALTHY)
        payload = hb.model_dump(mode="json")
        _, sig = _signed(priv, payload)
        code, body = _request(port, "POST", "/v0/heartbeat", payload, signature=sig)
        assert code == 200 and body["commands"] == []

        code, _ = _request(port, "POST", f"/v0/agents/{agent_id}/isolate",
                           {"isolated": True}, token="admin")
        assert code == 200
        hb2 = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                        message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                        status=AgentStatus.HEALTHY)
        p2 = hb2.model_dump(mode="json")
        _, sig2 = _signed(priv, p2)
        code, body = _request(port, "POST", "/v0/heartbeat", p2, signature=sig2)
        assert code == 200 and len(body["commands"]) == 1, body
        command = body["commands"][0]
        assert command["kind"] == "isolate" and command["payload"]["isolated"] is True

        ack = {"agent_id": agent_id, "command_id": command["command_id"],
               "status": "acked", "result": {"isolated": True},
               "nonce": uuid.uuid4().hex,
               "sent_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        _, ack_sig = _signed(priv, ack)
        code, body = _request(port, "POST", "/v0/commands/ack", ack,
                              signature=ack_sig)
        assert code == 200 and body["status"] == "acked", body

        hb3 = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                        message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                        status=AgentStatus.HEALTHY)
        p3 = hb3.model_dump(mode="json")
        _, sig3 = _signed(priv, p3)
        code, body = _request(port, "POST", "/v0/heartbeat", p3, signature=sig3)
        assert code == 200 and body["commands"] == []
        assert store.agent(agent_id).isolated is True
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_approval_confirm_enqueues_command(tmp_path):
    store, server, port, agent_id, priv = _setup(tmp_path)
    try:
        code, body = _request(port, "POST", "/v0/approvals",
                              {"kind": "confirm", "target": f"agent:{agent_id}",
                               "payload": {"agent_id": agent_id,
                                           "confirmation_id": "cid-1"}},
                              token="admin")
        assert code == 201, body
        approval_id = body["approval_id"]
        code, body = _request(port, "POST", f"/v0/approvals/{approval_id}/approve",
                              {}, token="approver")
        assert code == 200, body
        pending = store.pending_commands(agent_id)
        assert len(pending) == 1
        assert pending[0]["kind"] == "confirm"
        assert pending[0]["payload"]["confirmation_id"] == "cid-1"

        hb = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                       message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                       status=AgentStatus.HEALTHY)
        payload = hb.model_dump(mode="json")
        _, sig = _signed(priv, payload)
        code, body = _request(port, "POST", "/v0/heartbeat", payload, signature=sig)
        assert code == 200 and body["commands"][0]["kind"] == "confirm"
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_command_list_and_enqueue(tmp_path):
    store, server, port, agent_id, _ = _setup(tmp_path)
    try:
        code, body = _request(port, "POST", f"/v0/agents/{agent_id}/commands",
                              {"kind": "noop", "payload": {"x": 1}}, token="admin")
        assert code == 201 and body["kind"] == "noop", body
        code, body = _request(port, "GET", f"/v0/agents/{agent_id}/commands",
                              token="viewer")
        assert code == 200 and len(body["commands"]) == 1
        assert body["commands"][0]["status"] == "pending"
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_reports_and_audit(tmp_path):
    store, server, port, agent_id, priv = _setup(tmp_path)
    try:
        report = Report(tenant_id="t", agent_id=agent_id, connector_id="c",
                        message_id="m1", nonce=uuid.uuid4().hex,
                        report_id="r1", priority=Priority.P0, kind="incident",
                        payload={"x": 1})
        payload = {"reports": [report.model_dump(mode="json")]}
        _, sig = _signed(priv, payload)
        code, body = _request(port, "POST", "/v0/reports", payload, signature=sig)
        assert code == 200 and body["acked"] == ["r1"], body
        code, body = _request(port, "GET", "/v0/audit/verify", token="admin")
        assert code == 200 and body["ok"] is True
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_100_synthetic_heartbeats_p95(tmp_path):
    store, server, port, agent_id, priv = _setup(tmp_path)
    try:
        latencies = []
        for _ in range(100):
            hb = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                           message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                           status=AgentStatus.HEALTHY)
            payload = hb.model_dump(mode="json")
            _, sig = _signed(priv, payload)
            started = time.perf_counter()
            code, _ = _request(port, "POST", "/v0/heartbeat", payload, signature=sig)
            latencies.append(time.perf_counter() - started)
            assert code == 200
        latencies.sort()
        p95 = latencies[int(len(latencies) * 0.95) - 1]
        assert p95 < 2.0, p95
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_100_agents_enrolled_and_heartbeat_concurrently(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    store, server, port, first_agent, priv = _setup(tmp_path)
    try:
        pubkey = (tmp_path / "key.pub").read_text(encoding="utf-8")
        agents = [first_agent]
        for i in range(99):
            token = store.create_enrol_token("t")
            code, body = _request(port, "POST", "/v0/enrol", {
                "tenant_id": "t", "enrolment_token": token, "hostname": f"h{i}",
                "os": "windows", "arch": "x64", "agent_version": "0.1.0",
                "pubkey": pubkey,
            })
            assert code == 201, body
            agents.append(body["agent_id"])

        def beat(agent_id: str) -> float:
            hb = Heartbeat(tenant_id="t", agent_id=agent_id, connector_id="c",
                           message_id=str(uuid.uuid4()), nonce=uuid.uuid4().hex,
                           status=AgentStatus.HEALTHY)
            payload = hb.model_dump(mode="json")
            start = time.perf_counter()
            _, sig = _signed(priv, payload)
            code, _ = _request(port, "POST", "/v0/heartbeat", payload, signature=sig)
            assert code == 200
            return time.perf_counter() - start

        with ThreadPoolExecutor(max_workers=20) as pool:
            latencies = sorted(pool.map(beat, agents))
        p95 = latencies[int(len(latencies) * 0.95) - 1]
        assert p95 < 2.0, p95
        code, body = _request(port, "GET", "/v0/agents", token="viewer")
        assert code == 200 and len(body["agents"]) == 100
    finally:
        server.shutdown()
        server.server_close()
        store.close()
