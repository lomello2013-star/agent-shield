"""Ensemble study: does combining v1 and v2 beat the better single model at a fixed
false-positive budget?

Compared at the same budget (union FPR <= 1 % and <= 0.1 % on benign holdout):
  * v1 alone, v2 alone;
  * union (either model alerts) with jointly tuned thresholds;
  * intersection (both alert) with jointly tuned thresholds;
  * max-score and mean-score ensembles.

Writes artifacts/ensemble_report.json. Thresholds are chosen on the benign half of
the evaluation rows and scored on the other half to avoid tuning on the test rows.
"""

from __future__ import annotations

import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.ml import OnnxModel

ML = os.path.join(HERE, "spikes", "06-ml")
OUT = os.path.join(HERE, "artifacts", "ensemble_report.json")


def pick_thresholds(s1_cal, s2_cal, y_cal, mode: str, budget: float,
                    grid: int = 26) -> tuple[float, float, float]:
    """Grid-search thresholds with FPR <= budget on the calibration rows."""
    neg = y_cal == 0
    qs = np.linspace(0.0002, 0.05, grid)
    t1s = np.quantile(s1_cal[neg], 1 - qs)
    t2s = np.quantile(s2_cal[neg], 1 - qs)
    best = (-1.0, t1s[0], t2s[0])
    for t1 in t1s:
        a1 = s1_cal >= t1
        for t2 in t2s:
            a2 = s2_cal >= t2
            mask = (a1 | a2) if mode == "union" else (a1 & a2)
            fpr = float((mask & neg).sum()) / max(1, int(neg.sum()))
            if fpr > budget:
                continue
            tpr = float((mask & ~neg).sum()) / max(1, int((~neg).sum()))
            if tpr > best[0]:
                best = (tpr, float(t1), float(t2))
    return best


def score_at(thresholds: tuple[float, float], s1, s2, y, mode: str) -> dict:
    t1, t2 = thresholds
    a1, a2 = s1 >= t1, s2 >= t2
    mask = (a1 | a2) if mode == "union" else (a1 & a2)
    neg, pos = y == 0, y == 1
    return {"tp": int((mask & pos).sum()), "fp": int((mask & neg).sum()),
            "tpr": round(float((mask & pos).sum() / max(1, pos.sum())), 4),
            "fpr": round(float((mask & neg).sum() / max(1, neg.sum())), 5),
            "thresholds": [round(t1, 6), round(t2, 6)]}


def main() -> None:
    cache = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = cache["Xte"][:6000].astype(np.float32), cache["yte"][:6000]
    v1 = OnnxModel(os.path.join(ML, "pe_model.onnx"), allow_unsigned=True)
    v2 = OnnxModel(os.path.join(ML, "pe_v2_model.onnx"), allow_unsigned=True)
    s1, s2 = v1.predict(X), v2.predict(X)

    cal = slice(0, 3000)          # threshold selection
    ev = slice(3000, 6000)        # scoring
    s1c, s2c, yc = s1[cal], s2[cal], y[cal]
    s1e, s2e, ye = s1[ev], s2[ev], y[ev]

    report: dict = {"rows_calibration": 3000, "rows_evaluation": 3000, "budgets": []}
    for budget in (0.001, 0.01):
        entry = {"budget_fpr": budget, "single": {}, "union": None,
                 "intersection": None, "max_score": None, "mean_score": None}
        neg = yc == 0
        for name, s in (("v1", s1c), ("v2", s2c)):
            t = float(np.quantile(s[neg], 1 - budget))
            neg_e = ye == 0
            mask = (s1e if name == "v1" else s2e) >= t
            entry["single"][name] = {
                "threshold": round(t, 6),
                "tpr": round(float((mask & ~neg_e).sum() / max(1, (~neg_e).sum())), 4),
                "fpr": round(float((mask & neg_e).sum() / max(1, neg_e.sum())), 5)}

        for mode in ("union", "intersection"):
            best = pick_thresholds(s1c, s2c, yc, mode, budget)
            scored = score_at((best[1], best[2]), s1e, s2e, ye, mode)
            scored["calibration_tpr"] = round(best[0], 4)
            entry[mode] = scored

        for name, combined in (("max_score", np.maximum(s1, s2)),
                               ("mean_score", (s1 + s2) / 2)):
            t = float(np.quantile(combined[cal][yc == 0], 1 - budget))
            mask = combined[ev] >= t
            neg_e = ye == 0
            entry[name] = {
                "threshold": round(t, 6),
                "tpr": round(float((mask & ~neg_e).sum() / max(1, (~neg_e).sum())), 4),
                "fpr": round(float((mask & neg_e).sum() / max(1, neg_e.sum())), 5)}
        report["budgets"].append(entry)

    b1 = report["budgets"][1]      # 1 % budget
    best_single = max(b1["single"]["v1"]["tpr"], b1["single"]["v2"]["tpr"])
    report["conclusion"] = {
        "best_single_tpr_at_1pct": best_single,
        "union_tpr": b1["union"]["tpr"],
        "intersection_tpr": b1["intersection"]["tpr"],
        "max_score_tpr": b1["max_score"]["tpr"],
        "ensemble_beats_single": max(b1["union"]["tpr"], b1["intersection"]["tpr"],
                                     b1["max_score"]["tpr"]) > best_single + 0.005,
        "note": "thresholds tuned on the first 3000 rows, scored on the last 3000",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
