"""F11 controls: which ingredient turns the native crash on?

Each control runs the real soak (600 s, 200 events/s) with exactly one ingredient
removed, in its own subprocess so a crash does not stop the series:

  baseline          — the ordinary soak (reference)
  no_faulthandler   — diagnostic instrumentation removed
  no_rules          — the regex engine (C code in python312.dll) removed
  single_thread     — health() on the main thread instead of a sampler thread

Writes artifacts/f11_controls.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
OUT = os.path.join(HERE, "artifacts", "f11_controls.json")
CRASH = (-1073741819, 3221225477)
DURATION = int(os.environ.get("DURATION_S", "600"))

CONTROLS = {
    "baseline": {},
    "no_faulthandler": {"AIDF_NO_FAULTHANDLER": "1"},
    "no_rules": {"AIDF_NO_RULES": "1"},
    "single_thread": {"AIDF_SINGLE_THREAD": "1"},
}


def main() -> int:
    only = os.environ.get("CONTROLS", "").split(",") if os.environ.get("CONTROLS") else None
    results = []
    for name, extra in CONTROLS.items():
        if only and name not in only:
            continue
        env = dict(os.environ, AIDF_SOAK_SECONDS=str(DURATION),
                   AIDF_NATIVE_PROBE="1", PYTHONIOENCODING="utf-8", **extra)
        started = time.time()
        completed = subprocess.run([PY, os.path.join(HERE, "scripts", "soak_daemon.py")],
                                   cwd=HERE, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", env=env,
                                   timeout=DURATION + 300)
        progress = [line for line in (completed.stdout or "").splitlines()
                    if line.startswith("[soak]")]
        last_t = None
        if progress:
            try:
                last_t = float(progress[-1].split("t=")[1].split("s")[0])
            except (IndexError, ValueError):
                last_t = None
        results.append({"control": name, "exit_code": completed.returncode,
                        "crashed": completed.returncode in CRASH,
                        "elapsed_s": round(time.time() - started, 1),
                        "last_progress_t": last_t})
        print(f"{name}: exit={completed.returncode} "
              f"crashed={results[-1]['crashed']} last_t={last_t}", flush=True)
    report = {"duration_s": DURATION, "results": results,
              "crashed": [r["control"] for r in results if r["crashed"]],
              "clean": [r["control"] for r in results if not r["crashed"]],
              "note": "one run per control is a data point, not proof: the crash is "
                      "intermittent, so a clean control must be repeated to count"}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({"crashed": report["crashed"], "clean": report["clean"]},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
