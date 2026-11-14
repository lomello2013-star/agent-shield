from stml.connector.rpc_server import AlreadyRunning, ConnectorRpcServer


def _methods():
    return {
        "ping": lambda _p: {"pong": True},
        "status": lambda _p: {"spool": 0},
    }


def test_call_ping_and_status(tmp_path):
    server = ConnectorRpcServer(_methods(), lock_path=tmp_path / "connector.lock")
    host, port = server.start()
    try:
        assert host == "127.0.0.1"
        assert port > 0
        assert server.call("ping")["result"] == {"pong": True}
        assert server.call("status")["result"] == {"spool": 0}
        assert server.call("missing")["error"]["code"] == "method_not_found"
    finally:
        server.stop()
    assert not (tmp_path / "connector.lock").exists()


def test_second_instance_is_rejected(tmp_path):
    lock = tmp_path / "connector.lock"
    first = ConnectorRpcServer(_methods(), lock_path=lock)
    first.start()
    try:
        second = ConnectorRpcServer(_methods(), lock_path=lock)
        try:
            second.start()
        except AlreadyRunning:
            pass
        else:
            raise AssertionError("second connector must not start")
    finally:
        first.stop()
