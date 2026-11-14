#!/usr/bin/env python3
"""AIDefender signed A/B update CLI.

Examples:
    python scripts/aidf_update.py sign --root build/agent --version 1.2.0 \
        --key update.key.pem --out agent-1.2.0.bundle.json
    python scripts/aidf_update.py verify --bundle ... --pubkey update.pub.pem
    python scripts/aidf_update.py apply --slots /var/lib/aidf/update \
        --bundle ... --pubkey ... --health-cmd "/opt/aidf/aidf_agent.py --once"
    python scripts/aidf_update.py rollback --slots /var/lib/aidf/update
    python scripts/aidf_update.py status --slots /var/lib/aidf/update
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.update_package import (  # noqa: E402
    apply_bundle,
    bundle_from_file,
    bundle_to_file,
    sign_bundle,
    verify_bundle,
)
from core.updater import DualSlot, UpdateError  # noqa: E402


def _read_files(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith(".") or "__pycache__" in rel:
            continue
        out[rel] = path.read_bytes()
    if not out:
        raise UpdateError(f"no files under {root}")
    return out


def _health(command: str):
    argv = shlex.split(command)
    def check() -> bool:
        try:
            completed = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0
    return check


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aidf-update")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sign = sub.add_parser("sign", help="build and sign a bundle")
    sign.add_argument("--root", required=True)
    sign.add_argument("--version", required=True)
    sign.add_argument("--key", required=True, help="Ed25519 private key PEM")
    sign.add_argument("--out", required=True)

    verify = sub.add_parser("verify", help="verify a bundle")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--pubkey", required=True)

    apply = sub.add_parser("apply", help="verify, stage and activate")
    apply.add_argument("--slots", required=True)
    apply.add_argument("--bundle", required=True)
    apply.add_argument("--pubkey", required=True)
    apply.add_argument("--health-cmd", default="")

    rollback = sub.add_parser("rollback", help="switch back to the previous slot")
    rollback.add_argument("--slots", required=True)

    status = sub.add_parser("status", help="show active slot")
    status.add_argument("--slots", required=True)

    args = parser.parse_args(argv)
    try:
        if args.cmd == "sign":
            files = _read_files(Path(args.root))
            bundle = sign_bundle(args.version, files, Path(args.key).read_bytes())
            bundle_to_file(bundle, args.out)
            print(json.dumps({"bundle": args.out, "version": args.version,
                              "files": len(files), "bytes": sum(map(len, files.values()))}))
            return 0
        if args.cmd == "verify":
            files = verify_bundle(bundle_from_file(args.bundle),
                                  Path(args.pubkey).read_bytes())
            print(json.dumps({"ok": True, "files": len(files),
                              "bytes": sum(map(len, files.values()))}))
            return 0
        if args.cmd == "apply":
            result = apply_bundle(args.slots, bundle_from_file(args.bundle),
                                  Path(args.pubkey).read_bytes(),
                                  health=_health(args.health_cmd) if args.health_cmd else None)
            print(json.dumps(result))
            return 0
        if args.cmd == "rollback":
            print(json.dumps(DualSlot(args.slots).rollback()))
            return 0
        if args.cmd == "status":
            print(json.dumps(DualSlot(args.slots).pointer()))
            return 0
    except (OSError, ValueError, UpdateError) as exc:
        print(f"aidf-update: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
