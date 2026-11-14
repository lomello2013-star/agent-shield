"""CLI: `python -m stml.connector run --console ...`."""

from __future__ import annotations

import argparse
import json
import os
import secrets

from stml.connector.agent_client import AgentClient
from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.rpc_server import ConnectorRpcServer
from stml.connector.service import Connector, ConnectorConfig
from stml.connector.transport import ConsoleTransport, HttpTransport


def _authkey() -> bytes:
    raw = os.environ.get("AIDF_AUTHKEY", "")
    return bytes.fromhex(raw) if raw else secrets.token_bytes(32)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stml-connector")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run the connector")
    run.add_argument("--tenant", default=os.environ.get("STML_TENANT", "default"))
    run.add_argument("--agent-id", default="")
    run.add_argument("--data-root", default=os.environ.get("AIDF_DATA", "."))
    run.add_argument("--agent-address", default=os.environ.get("AIDF_ADDRESS", ""))
    run.add_argument("--token", default=os.environ.get("AIDF_TOKEN", ""))
    run.add_argument("--spool", default="stml-connector.sqlite3")
    run.add_argument("--state", default="stml-connector-state.json")
    run.add_argument("--server-url", default="")
    run.add_argument("--rpc-port", type=int, default=0)
    run.add_argument("--rpc-lock", default="stml-connector.lock")
    run.add_argument("--once", action="store_true")
    run.add_argument("--max-ticks", type=int, default=None)
    run.add_argument("--console", action="store_true")

    sub.add_parser("contract", help="print the stml/v0 JSON schema")

    args = parser.parse_args(argv)
    if args.cmd == "contract":
        from stml.contracts import v0

        print(json.dumps(v0.Heartbeat.model_json_schema(), indent=2))
        return 0

    agent = None
    if args.agent_address:
        from core.ipc import default_address

        address = args.agent_address or default_address()
        if not args.token:
            parser.error("--token or AIDF_TOKEN is required with --agent-address")
        agent = AgentClient(address, _authkey(), args.token)

    config = ConnectorConfig(
        tenant_id=args.tenant,
        agent_id=args.agent_id,
        data_root=args.data_root,
        spool_path=args.spool,
        state_path=args.state,
    )
    spool = Spool(args.spool)
    tailer = JsonlTailer(args.state + ".tail")
    transport = HttpTransport(args.server_url) if args.server_url else ConsoleTransport()
    connector = Connector(config, agent, spool, tailer, transport)

    server = ConnectorRpcServer(
        {
            "ping": lambda _p: {"pong": True},
            "status": lambda _p: connector.status(),
            "heartbeat": lambda _p: connector.heartbeat().model_dump(mode="json"),
            "inventory": lambda _p: connector.inventory().model_dump(mode="json"),
        },
        port=args.rpc_port,
        lock_path=args.rpc_lock,
    )
    host, port = server.start()
    print(json.dumps({"connector": "running", "host": host, "port": port,
                      "agent_id": config.agent_id, "connector_id": config.connector_id}), flush=True)
    if args.console and not args.once and args.max_ticks is None:
        # console mode: live status until interrupted
        try:
            while True:
                connector.tick()
                print(json.dumps(connector.status(), ensure_ascii=False), flush=True)
                import time
                time.sleep(config.heartbeat_interval_s)
        except KeyboardInterrupt:
            pass
        finally:
            server.stop()
            spool.close()
        return 0

    connector.run(once=args.once, max_ticks=args.max_ticks)
    if args.once or args.console:
        print(json.dumps(connector.status(), ensure_ascii=False), flush=True)
    server.stop()
    spool.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
