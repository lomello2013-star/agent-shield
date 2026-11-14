from stml.connector.rpc_server import ConnectorRpcServer


def test_token_is_required_when_configured(tmp_path):
    server = ConnectorRpcServer({"ping": lambda _p: {"pong": True}},
                                lock_path=tmp_path / "c.lock", auth_token="secret")
    server.start()
    try:
        denied = server.call("ping", token="wrong")
        assert denied["error"]["code"] == "unauthorized"
        assert server.call("ping", token="secret")["result"] == {"pong": True}
        # lock file carries pid/port/token for the operator
        import json
        lock = json.loads((tmp_path / "c.lock").read_text(encoding="utf-8"))
        assert lock["token"] == "secret"
        assert lock["port"] > 0
    finally:
        server.stop()


def test_without_token_stays_backward_compatible(tmp_path):
    server = ConnectorRpcServer({"ping": lambda _p: {"pong": True}},
                                lock_path=tmp_path / "c.lock")
    server.start()
    try:
        assert server.call("ping")["result"] == {"pong": True}
    finally:
        server.stop()
