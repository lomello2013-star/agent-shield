import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from stml.connector.signing import generate_keypair
from stml.contracts.policy import canonical_policy
from stml.server.app import ServerConfig, start_server
from stml.server.store import Store
from stml.trust.service import TrustError


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
    config = ServerConfig(tenant_id="t", admin_token="admin", viewer_token="viewer",
                          approver_token="approver", require_approval=True,
                          trust_dir=str(tmp_path / "trust"))
    server, _ = start_server(store, config, port=0)
    port = server.server_address[1]
    agent_priv, agent_pub = tmp_path / "agent.pem", tmp_path / "agent.pub"
    generate_keypair(agent_priv, agent_pub)
    for i in range(2):
        token = store.create_enrol_token("t")
        code, body = _req(port, "POST", "/v0/enrol", {
            "tenant_id": "t", "enrolment_token": token, "hostname": f"h{i}",
            "os": "windows", "arch": "x64", "agent_version": "0.1.0",
            "pubkey": agent_pub.read_text(encoding="utf-8"),
        })
        assert code == 201, body
    return store, server, port


def _signed_policy(server, version="v1"):
    key = server.trust.active("policy")
    content = {"allowlist": []}
    canonical = canonical_policy("p1", version, "stable", content)
    return {
        "policy_id": "p1", "version": version, "channel": "stable", "content": content,
        "key_id": key["key_id"], "signature": server.trust.sign(key["key_id"], canonical),
    }


def test_key_registry_revoke_and_rotate(tmp_path):
    store, server, port = _setup(tmp_path)
    try:
        code, body = _req(port, "GET", "/v0/trust/keys", token="viewer")
        assert code == 200 and any(k["key_class"] == "policy" for k in body["keys"])
        code, key = _req(port, "POST", "/v0/trust/keys", {"key_class": "model"}, token="admin")
        assert code == 201 and key["key_class"] == "model"
        assert "private_path" not in key
        server.trust.sign(key["key_id"], b"x")
        code, _ = _req(port, "POST", f"/v0/trust/keys/{key['key_id']}/revoke", token="admin")
        assert code == 200
        try:
            server.trust.sign(key["key_id"], b"x")
        except TrustError:
            pass
        else:
            raise AssertionError("revoked key must not sign")
        code, rotated = _req(port, "POST", f"/v0/trust/keys/{key['key_id']}/rotate", token="admin")
        assert code == 201 and rotated["rotated_from"] == key["key_id"]
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_approval_required_and_sod(tmp_path):
    store, server, port = _setup(tmp_path)
    try:
        policy = _signed_policy(server)
        code, body = _req(port, "POST", "/v0/policies", policy, token="admin")
        assert code == 201 and body["approval_id"] > 0
        approval_id = body["approval_id"]

        code, _ = _req(port, "POST", "/v0/rollouts",
                       {"policy_id": "p1", "version": "v1", "percent": 50}, token="admin")
        assert code == 409  # not approved yet

        code, _ = _req(port, "POST", f"/v0/approvals/{approval_id}/approve", token="admin")
        assert code == 403  # SoD: Admin cannot approve

        code, _ = _req(port, "POST", f"/v0/approvals/{approval_id}/approve", token="approver")
        assert code == 200
        code, body = _req(port, "POST", "/v0/rollouts",
                          {"policy_id": "p1", "version": "v1", "percent": 50}, token="admin")
        assert code == 201 and body["applied"], body

        code, _ = _req(port, "POST", f"/v0/agents/{body['applied'][0]}/isolate",
                       {"isolated": True}, token="approver")
        assert code == 403  # SoD: Approver cannot kill-switch
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_audit_export_json_and_cef(tmp_path):
    store, server, port = _setup(tmp_path)
    try:
        code, body = _req(port, "GET", "/v0/audit/export", token="admin")
        assert code == 200 and body["audit"]
        req = Request(f"http://127.0.0.1:{port}/v0/audit/export?format=cef",
                      headers={"Authorization": "Bearer admin"})
        with urlopen(req, timeout=5) as resp:
            text = resp.read().decode()
        assert text.startswith("CEF:0|AIDefender|STML")
    finally:
        server.shutdown()
        server.server_close()
        store.close()
