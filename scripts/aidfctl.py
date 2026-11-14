r"""`aidfctl` — minimal CLI for the JSON-RPC daemon (ADR D10).

Auth material never comes from the command line by default:
  * ``AIDF_AUTHKEY`` (hex) — transport key;
  * ``AIDF_TOKEN`` — role token (viewer/operator/admin);
  * optional files ``--authkey-file`` / ``--token-file`` for scripted use.

Example:
    set AIDF_AUTHKEY=... & set AIDF_TOKEN=...
    python scripts/aidfctl.py --address \\.\pipe\aidf health
    python scripts/aidfctl.py confirm --params-file confirm.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ipc import RpcClient, RpcError, default_address


def _load_hex(path: str | None, env: str) -> bytes:
    if path:
        with open(path, "rb") as fh:
            return bytes.fromhex(fh.read().decode().strip())
    value = os.environ.get(env)
    if not value:
        raise SystemExit(f"missing {env} (or --authkey-file)")
    return bytes.fromhex(value)


def _load_token(path: str | None) -> str:
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    value = os.environ.get("AIDF_TOKEN")
    if not value:
        raise SystemExit("missing AIDF_TOKEN (or --token-file)")
    return value


def load_params(raw: str | None, path: str | None) -> dict:
    """Params from --params or --params-file (the file avoids native-quoting issues)."""
    if path:
        with open(path, encoding="utf-8") as fh:
            value = json.load(fh)
    else:
        value = json.loads(raw or "{}")
    if not isinstance(value, dict):
        raise ValueError("params must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aidfctl", description="AIDefender JSON-RPC client")
    parser.add_argument("--address", default=None)
    parser.add_argument("--authkey-file")
    parser.add_argument("--token-file")
    parser.add_argument("method")
    parser.add_argument("--params", default=None)
    parser.add_argument("--params-file")
    args = parser.parse_args(argv)

    address = args.address or default_address()
    authkey = _load_hex(args.authkey_file, "AIDF_AUTHKEY")
    token = _load_token(args.token_file)
    try:
        params = load_params(args.params, args.params_file)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": f"bad params: {exc}"}), file=sys.stderr)
        return 2

    try:
        client = RpcClient(address, authkey, token)
    except (RpcError, OSError, EOFError) as exc:
        print(json.dumps({"error": f"connect failed: {exc}"}), file=sys.stderr)
        return 3
    try:
        result = client.call(args.method, params)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except RpcError as exc:
        print(json.dumps({"error": exc.message, "code": exc.code}), file=sys.stderr)
        return 4
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
