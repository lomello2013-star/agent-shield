"""Guard events -> STML connector -> report transport (no Linux kernel needed)."""

from __future__ import annotations

import json

from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.service import Connector, ConnectorConfig
from stml.connector.transport import MemoryTransport


def test_guard_events_are_delivered(tmp_path):
    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "events.jsonl").write_text(json.dumps({
        "kind": "guard", "pid": 42, "process": "evil",
        "path": "/tmp/evil", "allow": False, "reason": "exec under writable path",
    }) + "\n", encoding="utf-8")
    cfg = ConnectorConfig(tenant_id="t", data_root=str(tmp_path),
                          spool_path=str(tmp_path / "spool.sqlite3"),
                          state_path=str(tmp_path / "state.json"),
                          os_name="linux", arch="x64", agent_version="1.0.0")
    transport = MemoryTransport()
    connector = Connector(cfg, None, Spool(cfg.spool_path),
                          JsonlTailer(tmp_path / "tail.json"), transport)
    connector.tick()
    reports = [r for r in transport.sent if r.kind == "guard"]
    assert len(reports) == 1
    assert reports[0].payload["path"] == "/tmp/evil"
    assert reports[0].payload["allow"] is False
