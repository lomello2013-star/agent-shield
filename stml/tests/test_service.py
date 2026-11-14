import json

from stml.connector.agent_client import AgentUnavailable
from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.service import Connector, ConnectorConfig
from stml.connector.transport import MemoryTransport


class FakeAgent:
    def __init__(self):
        self.down = False

    def health(self):
        if self.down:
            raise AgentUnavailable("down")
        return {"status": "healthy", "safe_mode": False, "uptime_s": 5}

    def stats(self):
        if self.down:
            raise AgentUnavailable("down")
        return {"os": "windows", "arch": "x64", "version": "0.1.0"}

    def immutable_check(self):
        if self.down:
            raise AgentUnavailable("down")
        return {"immutable": "ok"}

    def self_test(self):
        if self.down:
            raise AgentUnavailable("down")
        return {"ok": True, "failed": []}


def _connector(tmp_path, agent, transport):
    cfg = ConnectorConfig(tenant_id="t", data_root=str(tmp_path),
                          spool_path=str(tmp_path / "spool.sqlite3"),
                          state_path=str(tmp_path / "state.json"))
    return Connector(cfg, agent, Spool(cfg.spool_path),
                     JsonlTailer(tmp_path / "tail.json"), transport)


def test_tick_collects_and_flushes(tmp_path):
    events = tmp_path / "spool" / "events.jsonl"
    events.parent.mkdir(parents=True)
    events.write_text(json.dumps({"kind": "incident", "severity": "critical",
                                  "report_id": "evt-1"}) + "\n", encoding="utf-8")
    transport = MemoryTransport()
    connector = _connector(tmp_path, FakeAgent(), transport)
    connector.tick()
    assert connector.last_heartbeat.status.value == "healthy"
    assert connector.last_inventory.immutable_ok is True
    assert [r.report_id for r in transport.sent] == ["evt-1"]
    assert connector.spool.pending_count() == 0


def test_fallback_to_files_when_agent_down(tmp_path):
    events = tmp_path / "spool" / "events.jsonl"
    events.parent.mkdir(parents=True)
    events.write_text(json.dumps({"kind": "audit", "report_id": "a-1"}) + "\n",
                      encoding="utf-8")
    agent = FakeAgent()
    agent.down = True
    connector = _connector(tmp_path, agent, MemoryTransport())
    connector.tick()
    assert connector.last_heartbeat.status.value == "offline"
    assert connector.last_heartbeat.source == "files"
    assert connector.spool.pending_count() == 0  # flushed


def test_read_only_rpc_bridge(tmp_path):
    connector = _connector(tmp_path, FakeAgent(), MemoryTransport())
    assert connector.rpc_health()["status"] == "healthy"
    assert connector.rpc_stats()["version"] == "0.1.0"
    assert connector.rpc_self_test()["ok"] is True
    assert connector.rpc_immutable_check()["immutable"] == "ok"


class PlatformAgent:
    def health(self):
        return {"status": "ok", "safe_mode": {"safe_mode": False, "reason": ""}}

    def stats(self):
        return {"platform": {"os": "windows", "arch": "arm64", "version": "10.0.26100",
                             "capabilities": ["ipc", "rules"]}}

    def immutable_check(self):
        return {"immutable": "ok"}


def test_platform_block_and_safe_mode_mapping(tmp_path):
    connector = _connector(tmp_path, PlatformAgent(), MemoryTransport())
    connector.tick()
    assert connector.last_heartbeat.status.value == "healthy"
    assert connector.last_inventory.os == "windows"
    assert connector.last_inventory.arch == "arm64"
    assert connector.last_inventory.agent_version == "10.0.26100"
    assert connector.last_inventory.capabilities == ["ipc", "rules"]

    class SafeAgent(PlatformAgent):
        def health(self):
            return {"status": "safe", "safe_mode": {"safe_mode": True, "reason": "bad config"}}

    (tmp_path / "safe").mkdir()
    connector2 = _connector(tmp_path / "safe", SafeAgent(), MemoryTransport())
    connector2.tick()
    assert connector2.last_heartbeat.status.value == "safe_mode"
