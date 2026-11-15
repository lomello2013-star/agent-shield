#!/usr/bin/env python3
"""Linux kernel-level prevention daemon (fanotify).

Usage:
    sudo python3 scripts/aidf_linux_guard.py --config /etc/aidf/guard.toml
    sudo python3 scripts/aidf_linux_guard.py --config ... --out /var/lib/aidf/reports/events.jsonl
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent if (HERE.parent / "core").exists() else HERE
sys.path.insert(0, str(ROOT))

from core.fanotify_guard import GuardPolicy, run_guard  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aidf-linux-guard")
    ap.add_argument("--config", default="/etc/aidf/guard.toml")
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)
    if sys.platform != "linux":
        print("aidf-guard: Linux only", file=sys.stderr)
        return 2
    policy = GuardPolicy.load(args.config)
    if policy.mode not in ("audit", "enforce"):
        print("aidf-guard: mode must be audit|enforce", file=sys.stderr)
        return 2
    try:
        return run_guard(policy, out=args.out)
    except OSError as exc:
        print(f"aidf-guard: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
