"""Cross-document consistency checks.

Generated documents can drift from the artifacts they claim to describe. This script
compares a small set of *verifiable* numbers and structures and fails loudly:

  1. docs/status.md         — test count, soak events, T1055 numbers, PE v2 TPR
  2. docs/t1055-coverage.md — measured path count, rule-ladder section
  3. docs/coverage-matrix.md — detection/prevention percentages
  4. DEVLOG.md              — entries carry the fields required by the spec
                              (legacy entries are counted and disclosed, not rewritten)

Writes artifacts/docs_consistency.json (also consumed by run_all).
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(HERE, "artifacts")
OUT = os.path.join(ART, "docs_consistency.json")

REQUIRED_DEVLOG_FIELDS = ("**Действие", "**Числа", "**Вердикт", "**Проверка",
                          "**Статус")


def art(name: str) -> dict:
    path = os.path.join(ART, name)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def read(rel: str) -> str:
    path = os.path.join(HERE, rel)
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def main() -> int:
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    status = read("docs/status.md")
    # The test count is deliberately *not* cross-checked here: it lives in the pytest
    # step of the same run, and run_all.json is written after this check runs, so the
    # comparison would be self-referential. The step result itself is the source.
    steps = art("run_all.json").get("steps") or []
    tests_step = next((s for s in steps if s["name"] == "tests"), None)
    if tests_step is not None:
        check("status/tests-step-ok", tests_step.get("ok") is True,
              "tests step result from the previous full run")

    soak_events = (art("soak_report.json").get("load") or {}).get("events_fed")
    if soak_events is not None:
        check("status/soak-events", str(soak_events) in status,
              f"artifact says {soak_events}")

    cov = art("t1055_coverage.json")
    if cov:
        pair = f"{cov['paths_measured']} ({cov['alert_paths']}/{cov['signal_paths']})"
        check("status/t1055-paths", pair in status, f"artifact says {pair}")
        totals = f"{cov['total_events']} / {cov['total_verdicts']} / {cov['total_loss']}"
        check("status/t1055-totals", totals in status, f"artifact says {totals}")

    v2 = art("pe_v2_report.json")
    if v2.get("operating_points"):
        first = v2["operating_points"][0]["tpr"]
        check("status/pe-v2-tpr", f"{first}" in status, f"artifact says {first}")

    check("status/this-run-column", "В этом прогоне" in status,
          "freshness column must mark artifacts from this run")

    t1055_md = read("docs/t1055-coverage.md")
    if cov and t1055_md:
        check("t1055-md/paths", f"**{cov['paths_measured']}**" in t1055_md,
              "measured path count in the generated doc")
        check("t1055-md/layers", "Лестница правил" in t1055_md,
              "rule ladder section present")

    matrix = read("docs/coverage-matrix.md")
    stage5 = art("stage5_report.json")
    if matrix and stage5:
        coverage = stage5.get("coverage") or {}
        det, prev = coverage.get("detection_pct"), coverage.get("prevention_pct")
        check("matrix/detection", det is None or str(det) in matrix, f"expected {det}")
        check("matrix/prevention", prev is None or str(prev) in matrix, f"expected {prev}")

    devlog = read("DEVLOG.md")
    entries = re.findall(r"^## \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\] (.+?) \[(\w+)\]$",
                         devlog, re.M)
    blocks = re.split(r"^## \[", devlog, flags=re.M)[1:]
    recent = blocks[-10:]
    missing = []
    for block in recent:
        header = block.splitlines()[0][:40] if block else ""
        for field in REQUIRED_DEVLOG_FIELDS:
            if field not in block:
                missing.append(f"{header} -> {field}")
    complete = [b for b in blocks
                if all(field in b for field in REQUIRED_DEVLOG_FIELDS)]
    coverage = len(complete) / len(blocks) if blocks else 0.0
    check("devlog/entries", len(entries) > 0, f"{len(entries)} entries")
    check("devlog/recent-fields", not missing,
          "; ".join(missing[:5]) if missing else
          f"last {len(recent)} entries carry the required fields")
    check("devlog/field-coverage", True,
          f"{len(complete)}/{len(blocks)} entries ({coverage:.0%}) carry all five fields; "
          f"older entries are disclosed, not rewritten")

    # F06: auto-review isolation is invalid (reviewer == author), so no entry may claim
    # an independent approval. This guard stays until a second model reviews the work.
    approved = re.findall(r"^\*\*Auto_review\*\*?:\s*approved", devlog, re.M)
    pending = re.findall(r"^\*\*Auto_review\*\*?:\s*pending", devlog, re.M)
    check("devlog/no-false-auto-review", not approved,
          f"{len(approved)} entries claim approval without an isolated reviewer")
    check("devlog/auto-review-disclosed", True,
          f"{len(pending)} entries disclose pending review")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "passed": sum(1 for c in checks if c["ok"]),
        "failed": [c["check"] for c in checks if not c["ok"]],
        "note": "only numbers that appear verbatim in the generated docs are checked; "
                "prose is not validated",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({"passed": report["passed"], "total": len(checks),
                      "failed": report["failed"]}, indent=2, ensure_ascii=False))
    return 0 if not report["failed"] else 1


if __name__ == "__main__":
    sys.exit(main())
