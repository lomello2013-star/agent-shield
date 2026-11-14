import json
from urllib.request import Request, urlopen

from stml.server.app import ServerConfig, start_server
from stml.server.store import Store


def test_metrics_and_slo(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    config = ServerConfig(tenant_id="t", admin_token="admin", viewer_token="viewer")
    server, _ = start_server(store, config, port=0)
    port = server.server_address[1]
    try:
        req = Request(f"http://127.0.0.1:{port}/metrics",
                      headers={"Authorization": "Bearer admin"})
        with urlopen(req, timeout=5) as resp:
            text = resp.read().decode()
        assert "stml_agents" in text and "stml_uptime_seconds" in text
        req = Request(f"http://127.0.0.1:{port}/v0/slo",
                      headers={"Authorization": "Bearer admin"})
        with urlopen(req, timeout=5) as resp:
            slo = json.loads(resp.read().decode())
        assert slo["audit_ok"] is True
        assert slo["stats"]["agents"] == 0
        assert slo["targets"]["heartbeat_p95_s"] == 2.0
        assert slo["operator"]["sufficient_data"] is False
        assert slo["operator"]["s18"] is None

        for path in ("/v0/reports", "/v0/incidents", "/v0/modules", "/v0/ops"):
            req = Request(f"http://127.0.0.1:{port}{path}",
                          headers={"Authorization": "Bearer viewer"})
            with urlopen(req, timeout=5) as resp:
                assert resp.status == 200
    finally:
        server.shutdown()
        server.server_close()
        store.close()
