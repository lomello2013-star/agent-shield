import json

from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.service import Connector, ConnectorConfig
from stml.connector.transport import HttpTransport
from stml.server.app import ServerConfig, start_server
from stml.server.store import Store


class FakeAgent:
    def health(self):
        return {"status": "healthy", "safe_mode": False}

    def stats(self):
        return {"os": "windows", "arch": "x64", "version": "0.1.0"}

    def immutable_check(self):
        return {"immutable": "ok"}

    def self_test(self):
        return {"ok": True, "failed": []}


def _setup(tmp_path):
    store = Store(tmp_path / "server.sqlite3")
    config = ServerConfig(tenant_id="t", admin_token="admin", viewer_token="viewer")
    server, _ = start_server(store, config, port=0)
    port = server.server_address[1]
    enrol_token = store.create_enrol_token("t")
    cfg = ConnectorConfig(
        tenant_id="t", data_root=str(tmp_path),
        spool_path=str(tmp_path / "spool.sqlite3"),
        state_path=str(tmp_path / "state.json"),
        server_url=f"http://127.0.0.1:{port}", enrol_token=enrol_token,
        hostname="host1", os_name="windows", arch="x64",
    )
    connector = Connector(cfg, FakeAgent(), Spool(cfg.spool_path),
                          JsonlTailer(tmp_path / "tail.json"),
                          HttpTransport(cfg.server_url))
    return store, server, port, connector


def test_connector_enrols_and_sends_heartbeat(tmp_path):
    store, server, port, connector = _setup(tmp_path)
    try:
        connector.enrol_if_needed()
        connector.tick()
        agents = store.agents("t")
        assert len(agents) == 1
        assert agents[0].hostname == "host1"
        assert agents[0].status == "healthy"
        assert connector.isolated is False
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_isolated_connector_buffers_reports(tmp_path):
    store, server, port, connector = _setup(tmp_path)
    try:
        connector.enrol_if_needed()
        connector.tick()
        store.isolate(connector.config.agent_id, True)
        events = tmp_path / "spool" / "events.jsonl"
        events.parent.mkdir(parents=True)
        events.write_text(json.dumps({"kind": "incident", "report_id": "p0-1",
                                      "priority": "P0"}) + "\n", encoding="utf-8")
        connector.tick()
        assert connector.isolated is True
        assert connector.spool.pending_count() == 1  # not flushed while isolated
        store.isolate(connector.config.agent_id, False)
        connector.tick()
        assert connector.isolated is False
        assert connector.spool.pending_count() == 0
        assert [r["report_id"] for r in store.reports()] == ["p0-1"]
    finally:
        server.shutdown()
        server.server_close()
        store.close()
