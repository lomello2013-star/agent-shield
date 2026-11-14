"""CLI: connector run, key/package signing, contract dump."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys

from stml.connector.agent_client import AgentClient
from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.release import build_manifest, sign_manifest, verify_manifest
from stml.connector.rpc_server import ConnectorRpcServer
from stml.connector.service import Connector, ConnectorConfig
from stml.connector.signing import generate_keypair, load_private, load_public
from stml.connector.transport import ConsoleTransport, HttpTransport


def _authkey() -> bytes:
    raw = os.environ.get("AIDF_AUTHKEY", "")
    return bytes.fromhex(raw) if raw else secrets.token_bytes(32)


def _run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.package_manifest:
        if not args.package_pubkey:
            parser.error("--package-manifest requires --package-pubkey")
        manifest = json.loads(open(args.package_manifest, encoding="utf-8").read())
        errors = verify_manifest(manifest, load_public(args.package_pubkey), args.package_root)
        if errors:
            print(json.dumps({"package": "rejected", "errors": errors}), file=sys.stderr)
            return 2

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

    rpc_token = args.rpc_token or secrets.token_urlsafe(24)
    server = ConnectorRpcServer(
        {
            # 5 read-only RPC (S0.1b): ping, health, stats, self_test, immutable_check
            "ping": lambda _p: {"pong": True},
            "health": lambda _p: connector.rpc_health(),
            "stats": lambda _p: connector.rpc_stats(),
            "self_test": lambda _p: connector.rpc_self_test(),
            "immutable_check": lambda _p: connector.rpc_immutable_check(),
            # connector-level views
            "status": lambda _p: connector.status(),
            "heartbeat": lambda _p: connector.heartbeat().model_dump(mode="json"),
            "inventory": lambda _p: connector.inventory().model_dump(mode="json"),
        },
        port=args.rpc_port,
        lock_path=args.rpc_lock,
        auth_token=rpc_token,
    )
    host, port = server.start()
    print(json.dumps({"connector": "running", "host": host, "port": port,
                      "agent_id": config.agent_id, "connector_id": config.connector_id,
                      "rpc_auth": "lock-file"}), flush=True)

    if args.console and not args.once and args.max_ticks is None:
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
    run.add_argument("--rpc-token", default="")
    run.add_argument("--package-manifest", default="")
    run.add_argument("--package-pubkey", default="")
    run.add_argument("--package-root", default="")
    run.add_argument("--once", action="store_true")
    run.add_argument("--max-ticks", type=int, default=None)
    run.add_argument("--console", action="store_true")

    keygen = sub.add_parser("keygen", help="generate connector Ed25519 keypair")
    keygen.add_argument("--private", required=True)
    keygen.add_argument("--public", required=True)

    sign = sub.add_parser("sign-package", help="build and sign a connector manifest")
    sign.add_argument("--root", required=True)
    sign.add_argument("--version", required=True)
    sign.add_argument("--key", required=True)
    sign.add_argument("--out", required=True)

    verify = sub.add_parser("verify-package", help="verify a signed connector manifest")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--pubkey", required=True)
    verify.add_argument("--root", default="")

    sub.add_parser("contract", help="print the stml/v0 Heartbeat JSON schema")

    args = parser.parse_args(argv)
    if args.cmd == "contract":
        from stml.contracts import v0

        print(json.dumps(v0.Heartbeat.model_json_schema(), indent=2))
        return 0
    if args.cmd == "keygen":
        kid = generate_keypair(args.private, args.public)
        print(json.dumps({"key_id": kid, "private": args.private, "public": args.public}))
        return 0
    if args.cmd == "sign-package":
        manifest = sign_manifest(build_manifest(args.root, args.version), load_private(args.key))
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        print(json.dumps({"manifest": args.out, "key_id": manifest["key_id"],
                          "files": len(manifest["files"])}))
        return 0
    if args.cmd == "verify-package":
        manifest = json.loads(open(args.manifest, encoding="utf-8").read())
        errors = verify_manifest(manifest, load_public(args.pubkey), args.root or None)
        print(json.dumps({"ok": not errors, "errors": errors}))
        return 0 if not errors else 2
    return _run(args, parser)


if __name__ == "__main__":
    raise SystemExit(main())
