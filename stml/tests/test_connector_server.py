import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.server_client import ServerClient, ServerError
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


class _Resp:
    status = 200
    will_close = False

    def read(self):
        return b'{"ok": true}'


class _FlakyConn:
    def __init__(self):
        self.requests = 0

    def request(self, *args, **kwargs):
        self.requests += 1
        if self.requests < 3:
            raise OSError(10055, "no buffer space")

    def getresponse(self):
        return _Resp()

    def close(self):
        pass


def test_server_client_retries_wsanobufs():
    client = ServerClient("http://127.0.0.1:9", Ed25519PrivateKey.generate())
    conn = _FlakyConn()
    client._connect = lambda: conn  # type: ignore[method-assign]
    assert client._post("/v0/inventory", {}) == {"ok": True}
    assert conn.requests == 3


class _ConflictConn:
    """First attempt is a replay conflict: the server already accepted the message."""

    def __init__(self, status=409, body=b'{"error": "replayed nonce"}'):
        self.status = status
        self.body = body
        self.requests = 0

    def request(self, *args, **kwargs):
        self.requests += 1

    def getresponse(self):
        conn = self

        class Resp:
            status = conn.status
            will_close = False

            def read(self):
                return conn.body

        return Resp()

    def close(self):
        pass


def test_server_client_treats_replayed_nonce_as_ack():
    """A retried request reuses its nonce; 409 'replayed nonce' means 'already done'."""
    client = ServerClient("http://127.0.0.1:9", Ed25519PrivateKey.generate())
    conn = _ConflictConn()
    client._connect = lambda: conn  # type: ignore[method-assign]
    assert client._post("/v0/inventory", {}) == {"ok": True, "replayed": True}
    assert conn.requests == 1


def test_server_client_other_conflicts_still_raise():
    client = ServerClient("http://127.0.0.1:9", Ed25519PrivateKey.generate())
    conn = _ConflictConn(status=409, body=b'{"error": "isolated agent"}')
    client._connect = lambda: conn  # type: ignore[method-assign]
    try:
        client._post("/v0/inventory", {})
    except ServerError as exc:
        assert exc.status == 409
    else:  # pragma: no cover - the call must raise
        raise AssertionError("a non-replay 409 must raise ServerError")


def _make_connector(tmp_path):
    cfg = ConnectorConfig(
        tenant_id="t", data_root=str(tmp_path),
        spool_path=str(tmp_path / "spool.sqlite3"),
        state_path=str(tmp_path / "state.json"),
        server_url="http://127.0.0.1:9", enrol_token="x",
        hostname="h", os_name="windows", arch="x64",
    )
    return Connector(cfg, FakeAgent(), Spool(cfg.spool_path),
                     JsonlTailer(tmp_path / "tail.json"),
                     HttpTransport(cfg.server_url))


def test_successful_heartbeat_clears_sticky_error(tmp_path):
    """last_error must not stay set after a successful call (it did: 1 event, 2.5k lines)."""
    connector = _make_connector(tmp_path)
    connector.last_error = "server inventory: HTTP 409: replayed nonce"

    class OkServer:
        def heartbeat(self, hb):
            return {"ok": True, "isolated": False, "commands": []}

        def inventory(self, inv):
            return {"ok": True}

        def ack_command(self, command_id, status, result):
            return {"ok": True}

    connector.server = OkServer()  # type: ignore[assignment]
    connector.enrolled = True
    connector._last_inventory_at = 0.0
    connector.tick()
    assert connector.last_error == ""



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
