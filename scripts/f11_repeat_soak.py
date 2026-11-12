"""F11: repeat long soaks to catch the nondeterministic native crash.

Each round runs in its own subprocess, so a crash does not stop the campaign. The
runner records the exit code per round; 0xC0000005 (-1073741819) is flagged as a native
crash. Stack dumps from faulthandler land in artifacts/_stdout/soak_stacks.txt.

Writes artifacts/f11_repeat.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
OUT = os.path.join(HERE, "artifacts", "f11_repeat.json")
ROUNDS = int(os.environ.get("ROUNDS", "4"))
DURATION = int(os.environ.get("DURATION_S", "600"))
CRASH = (-1073741819, 3221225477)


def main() -> int:
    results = []
    for index in range(1, ROUNDS + 1):
        env = dict(os.environ, AIDF_SOAK_SECONDS=str(DURATION),
                   PYTHONIOENCODING="utf-8")
        started = time.time()
        completed = subprocess.run([PY, os.path.join(HERE, "scripts", "soak_daemon.py")],
                                   cwd=HERE, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", env=env,
                                   timeout=DURATION + 300)
        elapsed = round(time.time() - started, 1)
        crashed = completed.returncode in CRASH
        # how far the run got, from the progress lines
        progress = [line for line in (completed.stdout or "").splitlines()
                    if line.startswith("[soak]")]
        last_t = None
        if progress:
            try:
                last_t = float(progress[-1].split("t=")[1].split("s")[0])
            except (IndexError, ValueError):
                last_t = None
        results.append({"round": index, "exit_code": completed.returncode,
                        "crashed": crashed, "elapsed_s": elapsed,
                        "last_progress_t": last_t,
                        "stderr_tail": (completed.stderr or "").strip().splitlines()[-1:]})
        print(f"round {index}: exit={completed.returncode} crashed={crashed} "
              f"elapsed={elapsed}s last_t={last_t}", flush=True)
    crashes = sum(1 for r in results if r["crashed"])
    report = {
        "rounds": ROUNDS, "duration_s": DURATION,
        "crashes": crashes, "clean": ROUNDS - crashes,
        "results": results,
        "note": "subprocess isolation keeps the campaign alive across native crashes; "
                "stack dumps are in artifacts/_stdout/soak_stacks.txt",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({"crashes": crashes, "of": ROUNDS}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
