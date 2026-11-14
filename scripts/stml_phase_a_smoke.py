"""Phase A smoke: real agent daemon -> RPC -> STML connector -> inventory."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.daemon import Daemon, DaemonConfig
from core.ipc import RpcServer, build_daemon_registry, default_address
from stml.connector.agent_client import AgentClient
from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.service import Connector, ConnectorConfig
from stml.connector.transport import MemoryTransport


def main() -> int:
    root = tempfile.mkdtemp(prefix="stml-phase-a-")
    address = default_address("stml-phase-a-" + uuid.uuid4().hex)
    authkey = b"k" * 32
    daemon = Daemon(root, config=DaemonConfig(sources=[]), collectors=[],
                    collect_interval_s=0)
    rpc = RpcServer(address, authkey, {"operator": "operator", "admin": "admin"},
                    build_daemon_registry(daemon))
    daemon.start()
    rpc.start()
    try:
        agent = AgentClient(address, authkey, "operator")
        cfg = ConnectorConfig(tenant_id="t", data_root=root,
                              spool_path=os.path.join(root, "spool.sqlite3"),
                              state_path=os.path.join(root, "state.json"))
        connector = Connector(cfg, agent, Spool(cfg.spool_path),
                              JsonlTailer(Path(root) / "tail.json"), MemoryTransport())
        connector.tick()
        inv = connector.last_inventory
        result = {
            "health_status": connector.last_heartbeat.status.value,
            "health_source": connector.last_heartbeat.source,
            "os": inv.os if inv else None,
            "arch": inv.arch if inv else None,
            "agent_version": inv.agent_version if inv else None,
            "capabilities": inv.capabilities if inv else [],
            "immutable_ok": inv.immutable_ok if inv else None,
        }
        assert result["health_status"] == "healthy", result
        assert result["os"] != "unknown", result
        assert "ipc" in result["capabilities"], result
        print(json.dumps({"ok": True, **result}, indent=2))
        return 0
    finally:
        rpc.stop()
        daemon.stop()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
