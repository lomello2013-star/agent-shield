"""CLI: `python -m stml.server run|token|isolate|agents|audit`."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.request

from stml.server.app import ServerConfig, StmlServer
from stml.server.store import Store


def _request(url: str, token: str, method: str = "GET", body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token}",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stml-server")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run the Fleet Core server")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8080)
    run.add_argument("--db", default=os.environ.get("STML_DB", "stml-server.sqlite3"))
    run.add_argument("--tenant", default=os.environ.get("STML_TENANT", "default"))
    run.add_argument("--admin-token", default=os.environ.get("STML_ADMIN_TOKEN", ""))
    run.add_argument("--viewer-token", default=os.environ.get("STML_VIEWER_TOKEN", ""))
    run.add_argument("--enrol-token", default="")

    tok = sub.add_parser("token", help="create an enrolment token")
    tok.add_argument("--db", default="stml-server.sqlite3")
    tok.add_argument("--tenant", default="default")

    iso = sub.add_parser("isolate", help="TUI kill-switch: isolate an agent")
    iso.add_argument("agent_id")
    iso.add_argument("--url", default="http://127.0.0.1:8080")
    iso.add_argument("--admin-token", default=os.environ.get("STML_ADMIN_TOKEN", ""))
    iso.add_argument("--resume", action="store_true")

    lst = sub.add_parser("agents", help="list agents")
    lst.add_argument("--url", default="http://127.0.0.1:8080")
    lst.add_argument("--viewer-token", default=os.environ.get("STML_VIEWER_TOKEN", ""))

    aud = sub.add_parser("audit", help="verify audit chain")
    aud.add_argument("--url", default="http://127.0.0.1:8080")
    aud.add_argument("--admin-token", default=os.environ.get("STML_ADMIN_TOKEN", ""))

    args = parser.parse_args(argv)
    if args.cmd == "token":
        store = Store(args.db)
        print(store.create_enrol_token(args.tenant))
        return 0
    if args.cmd == "agents":
        print(json.dumps(_request(args.url.rstrip("/") + "/v0/agents", args.viewer_token), indent=2))
        return 0
    if args.cmd == "audit":
        print(json.dumps(_request(args.url.rstrip("/") + "/v0/audit/verify", args.admin_token), indent=2))
        return 0
    if args.cmd == "isolate":
        url = f"{args.url.rstrip('/')}/v0/agents/{args.agent_id}/isolate"
        print(json.dumps(_request(url, args.admin_token, "POST",
                                  {"isolated": not args.resume}), indent=2))
        return 0

    store = Store(args.db)
    admin = args.admin_token or secrets.token_urlsafe(24)
    viewer = args.viewer_token or secrets.token_urlsafe(24)
    enrol = args.enrol_token or store.create_enrol_token(args.tenant)
    config = ServerConfig(tenant_id=args.tenant, admin_token=admin,
                          viewer_token=viewer, db_path=args.db)
    server = StmlServer((args.host, args.port), store, config)
    print(json.dumps({"stml": "running", "url": f"http://{args.host}:{args.port}",
                      "tenant": args.tenant, "admin_token": admin,
                      "viewer_token": viewer, "enrol_token": enrol}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
