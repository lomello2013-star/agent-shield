"""VS1 integration: live agent -> connector -> console/status."""

import uuid

from core.ipc import RpcServer, build_daemon_registry, default_address
from stml.connector.agent_client import AgentClient
from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.rpc_server import ConnectorRpcServer
from stml.connector.service import Connector, ConnectorConfig
from stml.connector.transport import MemoryTransport


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
        return {"os": "windows", "arch": "x64", "version": "0.1.0"}

    def run_self_test(self):
        return {"ok": True, "failed": []}

    def pending_confirmations(self):
        return []

    def confirm(self, *args):
        return {}

    def stop(self):
        pass


def _connector(tmp_path, agent, transport):
    cfg = ConnectorConfig(tenant_id="t", data_root=str(tmp_path),
                          spool_path=str(tmp_path / "spool.sqlite3"),
                          state_path=str(tmp_path / "state.json"))
    return Connector(cfg, agent, Spool(cfg.spool_path),
                     JsonlTailer(tmp_path / "tail.json"), transport)


def test_live_agent_is_visible_in_status(tmp_path):
    address = default_address("stml-e2e-" + uuid.uuid4().hex)
    agent_server = RpcServer(address=address, authkey=b"k" * 32,
                             tokens={"viewer": "viewer"},
                             registry=build_daemon_registry(FakeDaemon()))
    agent_server.start()
    try:
        agent = AgentClient(address, b"k" * 32, "viewer")
        connector = _connector(tmp_path, agent, MemoryTransport())
        connector.tick()
        assert connector.last_heartbeat.status.value == "healthy"
        assert connector.last_heartbeat.source == "rpc"

        rpc = ConnectorRpcServer({
            "ping": lambda _p: {"pong": True},
            "status": lambda _p: connector.status(),
        }, port=0, lock_path=tmp_path / "connector.lock")
        rpc.start()
        try:
            status = rpc.call("status")["result"]
            assert status["agent_id"] == connector.config.agent_id
            assert status["heartbeat"]["status"] == "healthy"
            assert rpc.call("ping")["result"] == {"pong": True}
        finally:
            rpc.stop()
    finally:
        agent_server.stop()


class _FlakyTransport:
    def __init__(self):
        self.fail = True
        self.acked = []

    def send(self, reports):
        if self.fail:
            raise ConnectionError("server down")
        self.acked.extend(r.report_id for r in reports)
        return [r.report_id for r in reports]


def test_p0_survives_transport_failure(tmp_path):
    from stml.contracts.v0 import Priority, Report

    connector = _connector(tmp_path, None, _FlakyTransport())
    report = Report(tenant_id="t", agent_id="a", connector_id="c",
                    message_id="m", nonce="n" * 8, report_id="p0-1",
                    priority=Priority.P0, kind="incident", payload={})
    connector.spool.enqueue(report)
    connector.flush()
    assert connector.spool.p0_count() == 1
    connector.transport.fail = False
    import time
    time.sleep(1.2)  # first retry backoff is 1 s
    connector.flush()
    assert connector.spool.p0_count() == 0
