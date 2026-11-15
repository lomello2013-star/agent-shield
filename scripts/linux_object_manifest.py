#!/usr/bin/env python3
"""Build a SHA256 manifest for the Linux agent's loader + BPF objects."""
from __future__ import annotations

import argparse
import hashlib
import pathlib


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="/root/spike4")
    ap.add_argument("--out", default="packaging/linux/objects.sha256")
    args = ap.parse_args()
    src = pathlib.Path(args.src)
    names = ["loader"] + sorted(p.name for p in src.glob("*.bpf.o"))
    if (src / "aidf-enforce").exists():
        names.insert(1, "aidf-enforce")
    lines = []
    for name in names:
        path = src / name
        if not path.exists():
            raise SystemExit(f"missing {path}")
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    pathlib.Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.out}: {len(lines)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
