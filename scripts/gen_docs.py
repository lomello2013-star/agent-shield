"""F20: single entry point for all derived documents.

Regenerates the derived documents in dependency order and then verifies that they
agree with the artifacts. One command instead of remembering four scripts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
STEPS = [
    ("t1055 coverage matrix", "t1055_coverage.py"),
    ("stage summary", "final_summary.py"),
    ("devlog audit", "devlog_audit.py"),
    ("docs consistency", "docs_consistency.py"),
]


def main() -> int:
    steps = list(STEPS)
    if os.environ.get("AIDF_DEFER_CONSISTENCY") == "1":
        # run_all writes docs/status.md *after* the generators and then checks
        # consistency itself, so the check is deferred to avoid reading a stale status.
        steps = [s for s in steps if s[1] != "docs_consistency.py"]
    results = []
    for label, script in steps:
        completed = subprocess.run([PY, os.path.join(HERE, "scripts", script)],
                                   cwd=HERE, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace")
        results.append({"label": label, "script": script, "ok": completed.returncode == 0,
                        "tail": (completed.stdout or completed.stderr).strip().splitlines()[-1:]
                        if (completed.stdout or completed.stderr) else []})
        if completed.returncode != 0:
            break
    ok = all(r["ok"] for r in results)
    output = {"generated_at": __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).isoformat(), "ok": ok, "steps": results}
    path = os.path.join(HERE, "artifacts", "gen_docs.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)
    print(json.dumps({"ok": ok, "steps": [(r["label"], r["ok"]) for r in results]},
                     ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
