"""STML healthcheck for Python or Rust server."""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def get(url: str, path: str, token: str = "") -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    with urlopen(Request(url.rstrip("/") + path, headers=headers), timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--token", default="")
    ap.add_argument("--require-agents", action="store_true")
    args = ap.parse_args()
    try:
        code, health = get(args.url, "/health")
        if code != 200 or not health.get("ok"):
            print(json.dumps({"ok": False, "health": health}))
            return 1
        if args.require_agents:
            code, agents = get(args.url, "/v0/agents", args.token)
            if code != 200 or "agents" not in agents:
                print(json.dumps({"ok": False, "agents": agents}))
                return 1
        print(json.dumps({"ok": True, "health": health}, ensure_ascii=False))
        return 0
    except (HTTPError, URLError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
