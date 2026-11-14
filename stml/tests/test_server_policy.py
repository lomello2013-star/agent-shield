import json
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from stml.connector.signing import generate_keypair, key_id, load_private, sign
from stml.contracts.policy import canonical_policy
from stml.server.app import ServerConfig, start_server
from stml.server.store import Store


def _req(port, method, path, payload=None, token=""):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=headers)
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def _setup(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    policy_priv, policy_pub = tmp_path / "policy.pem", tmp_path / "policy.pub"
    generate_keypair(policy_priv, policy_pub)
    config = ServerConfig(tenant_id="t", admin_token="admin", viewer_token="viewer",
                          policy_pubkey=policy_pub.read_text(encoding="utf-8"),
                          require_approval=False)
    server, _ = start_server(store, config, port=0)
    port = server.server_address[1]
    agent_priv, agent_pub = tmp_path / "agent.pem", tmp_path / "agent.pub"
    generate_keypair(agent_priv, agent_pub)
    agents = []
    for i in range(2):
        token = store.create_enrol_token("t")
        code, body = _req(port, "POST", "/v0/enrol", {
            "tenant_id": "t", "enrolment_token": token, "hostname": f"h{i}",
            "os": "windows", "arch": "x64", "agent_version": "0.1.0",
            "pubkey": agent_pub.read_text(encoding="utf-8"),
        })
        assert code == 201, body
        agents.append(body["agent_id"])
    return store, server, port, agents, policy_priv, policy_pub


def _policy_body(policy_priv, policy_pub, version="v1", content=None):
    content = content or {"allowlist": []}
    canonical = canonical_policy("p1", version, "stable", content)
    return {
        "policy_id": "p1", "version": version, "channel": "stable", "content": content,
        "key_id": key_id(load_private(policy_priv).public_key()),
        "signature": sign(load_private(policy_priv), canonical),
    }


def test_signed_policy_dry_run_and_rollback(tmp_path):
    store, server, port, agents, policy_priv, policy_pub = _setup(tmp_path)
    try:
        body = _policy_body(policy_priv, policy_pub)
        code, resp = _req(port, "POST", "/v0/policies", body, token="admin")
        assert code == 201, resp
        code, resp = _req(port, "POST", "/v0/policies", body, token="admin")
        assert code == 409

        code, resp = _req(port, "POST", "/v0/policies/p1/v1/dry-run", {}, token="viewer")
        assert code == 200 and resp["would_change"] == 2, resp

        code, resp = _req(port, "POST", "/v0/rollouts",
                          {"policy_id": "p1", "version": "v1", "percent": 50}, token="admin")
        assert code == 201 and len(resp["applied"]) == 1, resp
        rollout_id = resp["rollout_id"]
        code, resp = _req(port, "GET", f"/v0/rollouts/{rollout_id}", token="viewer")
        assert code == 200 and resp["status"] == "running"

        code, _ = _req(port, "POST", f"/v0/rollouts/{rollout_id}/rollback", {}, token="admin")
        assert code == 200
        code, resp = _req(port, "GET", "/v0/agents", token="viewer")
        assert all(a["policy_version"] is None for a in resp["agents"]), resp
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_bad_policy_signature_rejected(tmp_path):
    store, server, port, agents, policy_priv, policy_pub = _setup(tmp_path)
    try:
        body = _policy_body(policy_priv, policy_pub)
        body["signature"] = "AAAA"
        code, _ = _req(port, "POST", "/v0/policies", body, token="admin")
        assert code == 403
    finally:
        server.shutdown()
        server.server_close()
        store.close()
