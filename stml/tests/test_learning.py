import json

from stml.learning.service import LearningService, filter_event
from stml.server.app import ServerConfig, start_server
from stml.server.store import Store
from stml.trust.service import TrustService


def test_pii_filter_drops_raw_and_hashes_ids():
    event = {"kind": "exec", "path": "/tmp/x", "cmdline": "rm -rf /",
             "sha256": "abc", "pid": 42, "nested": {"hostname": "h", "ok": True}}
    out = filter_event(event, "salt")
    assert "path" not in out and "cmdline" not in out
    assert out["sha256"].startswith("h:")
    assert out["nested"] == {"ok": True}
    assert out["pid"] == 42


def test_consent_and_cases_and_models(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    trust = TrustService(store, tmp_path / "trust")
    learning = LearningService(store, trust, salt="s")
    try:
        try:
            learning.ingest("a", [{"kind": "x"}], False)
        except PermissionError:
            pass
        else:
            raise AssertionError("consent required")
        assert learning.ingest("a", [{"kind": "x", "path": "/secret"}], True) == 1
        assert store.telemetry()[0]["payload"] == {"kind": "x"}

        learning.add_case("c1", "r1", "TP", False, {"f": 1})
        assert store.cases()[0]["label"] == "TP"

        first = learning.register_model("pe", "v1", {"tpr_at_fpr": 0.9, "fp_budget": 0.01})
        assert learning.regress(first["model_id"])["ok"] is True
        learning.activate(first["model_id"])
        assert store.active_model()["version"] == "v1"

        worse = learning.register_model("pe", "v2", {"tpr_at_fpr": 0.8, "fp_budget": 0.02})
        assert learning.regress(worse["model_id"])["ok"] is False
        assert store.model(worse["model_id"])["status"] == "rejected"

        better = learning.register_model("pe", "v3", {"tpr_at_fpr": 0.95, "fp_budget": 0.005})
        assert learning.regress(better["model_id"])["ok"] is True
        learning.activate(better["model_id"])
        assert store.active_model()["version"] == "v3"
        assert learning.rollback()["active"] == first["model_id"]
        assert store.active_model()["version"] == "v1"
    finally:
        store.close()


def test_learning_api(tmp_path):
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    store = Store(tmp_path / "db.sqlite3")
    config = ServerConfig(tenant_id="t", admin_token="admin", viewer_token="viewer")
    server, _ = start_server(store, config, port=0)
    port = server.server_address[1]

    def req(method, path, payload=None, token="admin"):
        data = json.dumps(payload).encode() if payload is not None else None
        r = Request(f"http://127.0.0.1:{port}{path}", data=data, method=method,
                    headers={"Content-Type": "application/json",
                             "Authorization": f"Bearer {token}"})
        try:
            with urlopen(r, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    try:
        assert req("POST", "/v0/telemetry", {"agent_id": "a", "consent": False,
                                             "events": [{"kind": "x"}]})[0] == 403
        assert req("POST", "/v0/telemetry", {"agent_id": "a", "consent": True,
                                             "events": [{"kind": "x"}]})[0] == 201
        code, body = req("POST", "/v0/models", {"name": "pe", "version": "v1",
                                                "metrics": {"tpr_at_fpr": 0.9,
                                                            "fp_budget": 0.01}})
        assert code == 201 and body["model_id"] > 0
        assert req("POST", f"/v0/models/{body['model_id']}/regress")[0] == 200
        assert req("POST", f"/v0/models/{body['model_id']}/activate")[0] == 200
        assert req("GET", "/v0/models", token="viewer")[1]["active"]["version"] == "v1"
    finally:
        server.shutdown()
        server.server_close()
        store.close()
