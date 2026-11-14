"""One-command parity CI: read/auth checks + self-contained write parity.

Requires running Python and Rust servers for the read phase; the write phase
starts its own temporary servers (PostgreSQL `stml_parity_write`).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python-url", default="http://127.0.0.1:8080")
    ap.add_argument("--python-viewer", required=True)
    ap.add_argument("--python-admin", required=True)
    ap.add_argument("--rust-url", default="http://127.0.0.1:18097")
    ap.add_argument("--rust-viewer", default="viewer")
    ap.add_argument("--rust-admin", default="admin")
    ap.add_argument("--no-write", action="store_true")
    ap.add_argument("--load-url", default="")
    args = ap.parse_args()

    report: dict = {"generated_at": datetime.now(timezone.utc).isoformat(),
                    "read": None, "write": None, "load": None}
    code, out = run([sys.executable, "scripts/stml_rust_parity.py",
                     "--python-url", args.python_url,
                     "--python-viewer", args.python_viewer,
                     "--python-admin", args.python_admin,
                     "--rust-url", args.rust_url,
                     "--rust-viewer", args.rust_viewer,
                     "--rust-admin", args.rust_admin])
    report["read"] = {"ok": code == 0, "output": out[-4000:]}
    ok = code == 0

    if not args.no_write:
        code, out = run([sys.executable, "scripts/stml_write_parity.py"])
        report["write"] = {"ok": code == 0, "output": out[-4000:]}
        ok = ok and code == 0

    if args.load_url:
        code, out = run([sys.executable, "scripts/stml_rust_load.py",
                         "--url", args.load_url])
        report["load"] = {"ok": code == 0, "output": out[-4000:]}
        ok = ok and code == 0

    Path("artifacts/stml_parity_ci.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": ok, "read": report["read"]["ok"],
                      "write": report["write"]["ok"] if report["write"] else None,
                      "load": report["load"]["ok"] if report["load"] else None},
                     ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
