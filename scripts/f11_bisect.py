"""F11: bisect the native crash (0xC0000005) by disabling one component per run."""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
OUT = os.path.join(HERE, "artifacts", "f11_bisect.json")
MODES = ["full", "no_audit", "no_validate", "no_rss"]
DURATION = os.environ.get("DURATION_S", "180")


def main() -> int:
    results = []
    for mode in MODES:
        env = dict(os.environ, MODE=mode, DURATION_S=DURATION,
                   PYTHONIOENCODING="utf-8")
        completed = subprocess.run([PY, os.path.join(HERE, "scripts",
                                                     "f11_bisect_child.py")],
                                   cwd=HERE, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", env=env,
                                   timeout=float(DURATION) + 120)
        code = completed.returncode
        # 0xC0000005 shows up as -1073741819 (or 3221225477 unsigned) on Windows
        crashed = code in (-1073741819, 3221225477)
        results.append({"mode": mode, "exit_code": code, "crashed": crashed,
                        "stdout": (completed.stdout or "").strip().splitlines()[-1:],
                        "stderr": (completed.stderr or "").strip().splitlines()[-2:]})
        print(f"{mode}: exit={code} crashed={crashed}", flush=True)
    report = {"duration_s": float(DURATION), "modes": results,
              "crashed_modes": [r["mode"] for r in results if r["crashed"]],
              "clean_modes": [r["mode"] for r in results if not r["crashed"]],
              "note": "a mode that never crashes points at the component it disables"}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({"crashed": report["crashed_modes"],
                      "clean": report["clean_modes"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
