import uuid

import pytest

from core.ipc import RpcServer, build_daemon_registry, default_address
from stml.connector.agent_client import AgentClient, AgentUnavailable


class _Log:
    def append(self, *args, **kwargs):
        pass


class _Gate:
    killed_rules = set()


class FakeDaemon:
    response_quarantine = None
    gate = _Gate()
    log = _Log()

    def health(self):
        return {"status": "healthy", "safe_mode": False}

    def stats(self):
        return {"os": "test", "arch": "x64", "version": "0.1.0"}

    def run_self_test(self):
        return {"ok": True, "failed": []}

    def pending_confirmations(self):
        return []

    def confirm(self, *args):
        return {}

    def stop(self):
        pass


@pytest.fixture()
def server():
    address = default_address("stml-test-" + uuid.uuid4().hex)
    srv = RpcServer(address=address, authkey=b"k" * 32,
                    tokens={"viewer-token": "viewer"},
                    registry=build_daemon_registry(FakeDaemon()))
    srv.start()
    try:
        yield address
    finally:
        srv.stop()


def test_health_and_stats(server):
    client = AgentClient(server, b"k" * 32, "viewer-token")
    assert client.health()["status"] == "healthy"
    assert client.stats()["version"] == "0.1.0"


def test_wrong_token_is_unavailable(server):
    client = AgentClient(server, b"k" * 32, "bad-token")
    with pytest.raises(AgentUnavailable):
        client.health()
