"""F09: choose the operating point that meets the E9 PPV target.

E9 asks for PPV >= 50 % at a 1/1000 prevalence. PPV depends on the operating point:
loosening FPR lowers PPV even when TPR rises. This script scans the measured operating
points of the PE v2 model and reports the PPV curve plus the tightest threshold that
still meets 50 % — that threshold becomes the policy default for alerting.

Writes artifacts/f09_ppv_target.json.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.gate import ppv as ppv_formula

ART = os.path.join(HERE, "artifacts")
OUT = os.path.join(ART, "f09_ppv_target.json")
PREVALENCE = 0.001
TARGET = 0.50


def main() -> None:
    with open(os.path.join(ART, "pe_v2_report.json"), encoding="utf-8") as fh:
        report = json.load(fh)
    points = report.get("operating_points") or []
    rows = []
    for point in points:
        fpr = point["fpr_measured"]
        tpr = point["tpr"]
        value = ppv_formula(tpr, fpr, PREVALENCE)
        rows.append({
            "target_fpr": point["target_fpr"],
            "threshold": point["threshold"],
            "tpr": tpr,
            "fpr": fpr,
            "ppv_at_prevalence": round(value, 4),
            "meets_target": value >= TARGET,
        })

    meeting = [r for r in rows if r["meets_target"]]
    # the *loosest* threshold that still meets the target keeps the most detections
    chosen = max(meeting, key=lambda r: r["fpr"]) if meeting else None
    output = {
        "model": report.get("model", "aidf-pe-ember-v2"),
        "prevalence": PREVALENCE,
        "target_ppv": TARGET,
        "curve": rows,
        "chosen": chosen,
        "looser_point_rejected": [
            r for r in rows if not r["meets_target"]
        ],
        "conclusion": (
            "P9 (E9) достижима только при ужесточении порога: на 1 % FPR PPV слишком низкий"
            if chosen is None else
            f"E9 достигается при FPR <= {chosen['fpr'] * 100:.2f} % "
            f"(threshold {chosen['threshold']}), TPR при этом {chosen['tpr']}"
        ),
        "note": "PPV считается по TPR/FPR в рабочей точке при prevalence 1/1000, "
                "а не по confidence"
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)
    print(json.dumps({"chosen": chosen, "meets_target": bool(chosen)}, ensure_ascii=False))
    for row in rows:
        print(f"  FPR {row['fpr']*100:.2f}% TPR {row['tpr']:.3f} -> PPV "
              f"{row['ppv_at_prevalence']*100:.1f}%")


if __name__ == "__main__":
    main()
