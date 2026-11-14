"""External watchdog probe for STML (line 1 / line 2 friendly).

Usage:
  python scripts/stml_watchdog.py --url http://127.0.0.1:8080 --token <admin> --once
Exit code 1 on failure; writes artifacts/stml_watchdog.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen


def probe(url: str, token: str, timeout: float = 5.0) -> dict:
    result = {"ts": time.time(), "url": url, "checks": {}}
    try:
        with urlopen(url.rstrip("/") + "/health", timeout=timeout) as resp:
            result["checks"]["health"] = json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001
        result.update(ok=False, error=f"health: {exc}")
        return result
    try:
        req = Request(url.rstrip("/") + "/v0/slo",
                      headers={"Authorization": f"Bearer {token}"})
        with urlopen(req, timeout=timeout) as resp:
            slo = json.loads(resp.read().decode())
        result["checks"]["slo"] = slo
        result["ok"] = bool(slo.get("audit_ok", False))
        if not result["ok"]:
            result["error"] = "audit chain not ok"
    except Exception as exc:  # noqa: BLE001
        result.update(ok=False, error=f"slo: {exc}")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("STML_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--token", default=os.environ.get("STML_ADMIN_TOKEN", ""))
    parser.add_argument("--out", default="artifacts/stml_watchdog.json")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    while True:
        result = probe(args.url, args.token)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps({"ok": result.get("ok"), "error": result.get("error")}), flush=True)
        if args.once:
            return 0 if result.get("ok") else 1
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
