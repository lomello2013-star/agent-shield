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
    # Strictness: every artifact-backed check is registered unconditionally and fails
    # when its source is missing. Silently skipping a check turns 15/15 into 13/13 while
    # still exiting 0 — that hid real gaps (P0-3).
    steps = art("run_all.json").get("steps") or []
    tests_step = next((s for s in steps if s.get("name") == "tests"), None)
    status_count = re.search(r"\| tests \| ok \| (\d+) passed", status)
    step_detail = tests_step.get("detail", "") if tests_step else ""
    step_count = re.search(r"(\d+) passed", step_detail)
    counts_match = bool(status_count and step_count
                        and status_count.group(1) == step_count.group(1))
    check("status/tests-step-ok",
          tests_step is not None and tests_step.get("ok") is True and counts_match,
          "run_all.json missing tests step" if tests_step is None
          else (f"status={status_count.group(1) if status_count else '?'} "
                f"artifact={step_count.group(1) if step_count else '?'}"))

    soak_events = (art("soak_report.json").get("load") or {}).get("events_fed")
    check("status/soak-events",
          soak_events is not None and str(soak_events) in status,
          "soak_report.json has no load.events_fed" if soak_events is None
          else f"artifact says {soak_events}")

    cov = art("t1055_coverage.json")
    paths_ok = all(k in cov for k in ("paths_measured", "alert_paths", "signal_paths"))
    pair = (f"{cov['paths_measured']} ({cov['alert_paths']}/{cov['signal_paths']})"
            if paths_ok else "")
    check("status/t1055-paths", paths_ok and pair in status,
          f"artifact says {pair}" if paths_ok else "t1055_coverage.json missing path fields")
    totals_ok = all(k in cov for k in ("total_events", "total_verdicts", "total_loss"))
    totals = (f"{cov['total_events']} / {cov['total_verdicts']} / {cov['total_loss']}"
              if totals_ok else "")
    check("status/t1055-totals", totals_ok and totals in status,
          f"artifact says {totals}" if totals_ok else "t1055_coverage.json missing totals")

    v2 = art("pe_v2_report.json")
    points = v2.get("operating_points") or []
    check("status/pe-v2-tpr",
          bool(points) and str(points[0]["tpr"]) in status,
          "pe_v2_report.json has no operating_points" if not points
          else f"artifact says {points[0]['tpr']}")

    check("status/this-run-column", "В этом прогоне" in status,
          "freshness column must mark artifacts from this run")

    t1055_md = read("docs/t1055-coverage.md")
    md_paths_ok = (bool(cov) and paths_ok and bool(t1055_md)
                   and f"**{cov['paths_measured']}**" in t1055_md)
    check("t1055-md/paths", md_paths_ok,
          "t1055-coverage.md missing or has no measured count")
    check("t1055-md/layers", bool(t1055_md) and "Лестница правил" in t1055_md,
          "t1055-coverage.md missing rule ladder")

    matrix = read("docs/coverage-matrix.md")
    stage5 = art("stage5_report.json")
    coverage = stage5.get("coverage") or {}
    det, prev = coverage.get("detection_pct"), coverage.get("prevention_pct")
    check("matrix/detection",
          bool(matrix) and det is not None and str(det) in matrix,
          "coverage-matrix.md or stage5 detection_pct missing"
          if not matrix or det is None else f"expected {det}")
    check("matrix/prevention",
          bool(matrix) and prev is not None and str(prev) in matrix,
          "coverage-matrix.md or stage5 prevention_pct missing"
          if not matrix or prev is None else f"expected {prev}")

    devlog = read("DEVLOG.md")
    entries = re.findall(r"^## \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\] (.+?) \[(\w+)\]$",
                         devlog, re.M)
    blocks = re.split(r"^## \[", devlog, flags=re.M)[1:]
    recent = blocks[-10:]
    missing = []
    review_fields = ("**Статус",)
    # review/correction/report entries carry their own field set (Вердикт + Статус)
    relaxed_types = ("[auto_review]", "[escalation]", "[report]", "[decision]",
                     "[incident]", "[system-action]")
    for block in recent:
        header = block.splitlines()[0][:40] if block else ""
        fields = (review_fields if any(marker in block.splitlines()[0]
                                       for marker in relaxed_types)
                  else REQUIRED_DEVLOG_FIELDS)
        for field in fields:
            if field not in block:
                missing.append(f"{header} -> {field}")
    check("devlog/entries", len(entries) > 0, f"{len(entries)} entries")
    check("devlog/recent-fields", not missing,
          "; ".join(missing[:5]) if missing else
          f"last {len(recent)} entries carry the required fields")

    # F06: auto-review isolation is invalid (reviewer == author), so no entry may claim
    # an independent approval. This guard stays until a second model reviews the work.
    approved = re.findall(r"^\*\*Auto_review\*\*?:\s*approved", devlog, re.M)
    check("devlog/no-false-auto-review", not approved,
          f"{len(approved)} entries claim approval without an isolated reviewer")

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
