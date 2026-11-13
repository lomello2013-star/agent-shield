import threading
import time

import pytest

from core.ipc import (
    ADMIN_METHODS,
    FORBIDDEN,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    UNAUTHORIZED,
    OPERATOR_METHODS,
    RpcClient,
    RpcError,
    RpcRegistry,
    RpcServer,
    build_daemon_registry,
    free_pipe_name,
    generate_token,
)


def echo(params):
    return {"echo": params.get("x")}


def boom(params):
    raise RuntimeError("handler exploded")


def make_registry():
    reg = RpcRegistry()
    reg.register("ping", {"viewer", "operator", "admin"}, lambda p: {"pong": True})
    reg.register("echo", {"viewer", "operator", "admin"}, echo)
    reg.register("quarantine", {"operator", "admin"}, lambda p: {"ok": True})
    reg.register("kill_switch", {"admin"}, lambda p: {"killed": True})
    reg.register("boom", {"admin"}, boom)
    return reg


# ------------------------------------------------------------------- registry
def test_dispatch_success():
    response = make_registry().dispatch(
        {"jsonrpc": "2.0", "id": 7, "method": "echo", "params": {"x": 42}}, "viewer")
    assert response == {"jsonrpc": "2.0", "id": 7, "result": {"echo": 42}}


def test_dispatch_invalid_requests():
    reg = make_registry()
    assert reg.dispatch("nope", "viewer")["error"]["code"] == INVALID_REQUEST
    assert reg.dispatch({"id": 1, "method": "ping"}, "viewer")["error"]["code"] == INVALID_REQUEST
    assert reg.dispatch({"jsonrpc": "2.0", "method": "ping"}, "viewer")["error"]["code"] == INVALID_REQUEST
    assert reg.dispatch({"jsonrpc": "1.0", "id": 1, "method": "ping"}, "viewer")["error"]["code"] == INVALID_REQUEST


def test_dispatch_unknown_method():
    response = make_registry().dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "format_disk"}, "admin")
    assert response["error"]["code"] == METHOD_NOT_FOUND


def test_dispatch_role_forbidden():
    response = make_registry().dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "kill_switch", "params": {}}, "viewer")
    assert response["error"]["code"] == FORBIDDEN


def test_dispatch_handler_exception_is_internal_error():
    response = make_registry().dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "boom"}, "admin")
    assert response["error"]["code"] == INTERNAL_ERROR
    assert "RuntimeError" in response["error"]["message"]


def test_methods_for_role():
    reg = make_registry()
    assert set(reg.methods_for("viewer")) == {"ping", "echo"}
    assert set(reg.methods_for("operator")) == {"ping", "echo", "quarantine"}
    assert set(reg.methods_for("admin")) == set(reg.methods_for("admin"))


def test_register_requires_roles():
    with pytest.raises(ValueError):
        RpcRegistry().register("x", set(), lambda p: None)


def test_role_sets_are_nested():
    assert set(OPERATOR_METHODS) > set({"health", "stats"})
    assert ADMIN_METHODS > OPERATOR_METHODS


# --------------------------------------------------------------------- server
@pytest.fixture
def server_setup():
    address = free_pipe_name()
    authkey = b"k" * 32
    admin = generate_token()
    viewer = generate_token()
    server = RpcServer(address=address, authkey=authkey,
                       tokens={admin: "admin", viewer: "viewer"},
                       registry=make_registry())
    server.start()
    time.sleep(0.05)
    try:
        yield address, authkey, admin, viewer
    finally:
        server.stop()


def test_hello_and_call(server_setup):
    address, authkey, admin, _ = server_setup
    client = RpcClient(address, authkey, admin)
    try:
        assert client.role == "admin"
        assert client.call("ping") == {"pong": True}
        assert client.call("echo", {"x": 1}) == {"echo": 1}
    finally:
        client.close()


def test_bad_token_is_rejected(server_setup):
    address, authkey, _, _ = server_setup
    with pytest.raises(RpcError) as exc:
        RpcClient(address, authkey, "wrong-token")
    assert exc.value.code == UNAUTHORIZED


def test_wrong_authkey_cannot_connect(server_setup):
    address, _, admin, _ = server_setup
    with pytest.raises(Exception):
        RpcClient(address, b"x" * 32, admin)


def test_viewer_cannot_call_admin_method(server_setup):
    address, authkey, _, viewer = server_setup
    client = RpcClient(address, authkey, viewer)
    try:
        assert client.role == "viewer"
        with pytest.raises(RpcError) as exc:
            client.call("kill_switch", {"rule_id": "R-1"})
        assert exc.value.code == FORBIDDEN
    finally:
        client.close()


def test_concurrent_clients(server_setup):
    address, authkey, admin, _ = server_setup

    results = []

    def worker():
        client = RpcClient(address, authkey, admin)
        try:
            results.append(client.call("ping"))
        finally:
            client.close()

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert len(results) == 5 and all(r == {"pong": True} for r in results)


def test_daemon_registry_health_requires_viewer():
    class FakeDaemon:
        response_quarantine = None

        def health(self):
            return {"status": "ok"}

        def stats(self):
            return {"pipeline": {}}

    reg = build_daemon_registry(FakeDaemon())
    assert reg.dispatch({"jsonrpc": "2.0", "id": 1, "method": "health"}, "viewer")["result"] == {"status": "ok"}
    response = reg.dispatch({"jsonrpc": "2.0", "id": 2, "method": "quarantine",
                             "params": {"path": "x"}}, "viewer")
    assert response["error"]["code"] == FORBIDDEN


def test_daemon_registry_quarantine_without_store_is_error():
    class FakeDaemon:
        response_quarantine = None

    reg = build_daemon_registry(FakeDaemon())
    response = reg.dispatch({"jsonrpc": "2.0", "id": 1, "method": "quarantine",
                             "params": {"path": "x"}}, "operator")
    assert response["error"]["code"] == INTERNAL_ERROR


def test_recv_frame_enforces_size_before_unpickle():
    """P0-5: an oversized frame is rejected before deserialization."""
    from multiprocessing import Pipe

    srv = RpcServer(address="x", authkey=b"k", tokens={}, registry=make_registry(),
                    max_message=1024)
    parent, child = Pipe()
    try:
        child.send({"id": 1, "method": "ping", "blob": "x" * 5000})
        with pytest.raises(OSError):
            srv._recv_frame(parent)
    finally:
        parent.close()
        child.close()
