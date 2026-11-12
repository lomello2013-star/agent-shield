"""F11: focused test — is the crash in the re-validation path (pydantic-core)?

The crash-time stack showed the main thread inside `Event.model_validate` called from
`Pipeline.run_once`, i.e. the *second* validation of an event that was already validated
on submission. This runner compares `full` against `no_validate` (which skips the second
validation) at a higher event rate so the validation count is reached faster.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
OUT = os.path.join(HERE, "artifacts", "f11_pydantic_focus.json")
CRASH = (-1073741819, 3221225477)
MODES = os.environ.get("MODES", "full,no_validate").split(",")
REPS = int(os.environ.get("REPS", "3"))
DURATION = os.environ.get("DURATION_S", "240")
RATE = os.environ.get("RATE", "800")


def main() -> int:
    results = []
    for rep in range(1, REPS + 1):
        for mode in MODES:
            env = dict(os.environ, MODE=mode, DURATION_S=DURATION, RATE=RATE,
                       PYTHONIOENCODING="utf-8")
            started = time.time()
            completed = subprocess.run(
                [PY, os.path.join(HERE, "scripts", "f11_bisect_child.py")],
                cwd=HERE, capture_output=True, text=True,
                encoding="utf-8", errors="replace", env=env,
                timeout=float(DURATION) + 120)
            results.append({
                "rep": rep, "mode": mode, "exit_code": completed.returncode,
                "crashed": completed.returncode in CRASH,
                "elapsed_s": round(time.time() - started, 1),
                "stdout_tail": (completed.stdout or "").strip().splitlines()[-1:],
            })
            print(f"rep {rep} {mode}: exit={completed.returncode} "
                  f"crashed={results[-1]['crashed']} in {results[-1]['elapsed_s']}s",
                  flush=True)
    summary = {}
    for mode in MODES:
        rows = [r for r in results if r["mode"] == mode]
        summary[mode] = {"runs": len(rows), "crashes": sum(1 for r in rows if r["crashed"])}
    report = {"duration_s": float(DURATION), "rate": float(RATE), "reps": REPS,
              "summary": summary, "results": results,
              "note": "if 'full' crashes and 'no_validate' never does, the second "
                      "validation in Pipeline.run_once is implicated"}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
