"""Analyse v1 vs v2 alert disagreements (decision-relevant, not just a percentage).

For the same 5 000 holdout rows and each model's own 1 %-FPR threshold, classify:
  * v2-only TP / v1-only TP     -> net detection gain of v2
  * v2-only FP / v1-only FP     -> net false-positive change
  * near-threshold share        -> how much of the disagreement is instability
Feature names are not available in this EMBER mirror, so feature diffs are reported
as indices only (a lead, not a claim).

Writes artifacts/disagreement_report.json.
"""

from __future__ import annotations

import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.ml import OnnxModel, fpr_threshold

ML = os.path.join(HERE, "spikes", "06-ml")
OUT = os.path.join(HERE, "artifacts", "disagreement_report.json")


def main() -> None:
    cache = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = cache["Xte"][:5000].astype(np.float32), cache["yte"][:5000]
    v1 = OnnxModel(os.path.join(ML, "pe_model.onnx"), allow_unsigned=True)
    v2 = OnnxModel(os.path.join(ML, "pe_v2_model.onnx"), allow_unsigned=True)
    s1, s2 = v1.predict(X), v2.predict(X)
    thr1 = fpr_threshold(list(s1[y == 0]), 0.01)
    thr2 = fpr_threshold(list(s2[y == 0]), 0.01)
    a1, a2 = s1 >= thr1, s2 >= thr2

    groups = {
        "v2_only_tp": (a2 & ~a1 & (y == 1)),
        "v1_only_tp": (a1 & ~a2 & (y == 1)),
        "v2_only_fp": (a2 & ~a1 & (y == 0)),
        "v1_only_fp": (a1 & ~a2 & (y == 0)),
    }
    counts = {name: int(mask.sum()) for name, mask in groups.items()}

    def stats(mask) -> dict:
        if mask.sum() == 0:
            return {"n": 0}
        return {"n": int(mask.sum()),
                "v1_score_mean": round(float(s1[mask].mean()), 4),
                "v2_score_mean": round(float(s2[mask].mean()), 4),
                "delta_mean": round(float((s2[mask] - s1[mask]).mean()), 4),
                "delta_min": round(float((s2[mask] - s1[mask]).min()), 4),
                "delta_max": round(float((s2[mask] - s1[mask]).max()), 4)}

    # how much of the disagreement sits within 0.05 of the thresholds
    disagree = a1 != a2
    near = disagree & ((np.abs(s1 - thr1) < 0.05) | (np.abs(s2 - thr2) < 0.05))
    near_share = float(near.sum() / max(1, disagree.sum()))

    # feature lead: indices with the largest mean difference between v2-only TP
    # and v1-only TP (names unavailable in this dataset mirror)
    lead_indices = []
    if groups["v2_only_tp"].sum() and groups["v1_only_tp"].sum():
        diff = np.abs(X[groups["v2_only_tp"]].mean(0) - X[groups["v1_only_tp"]].mean(0))
        lead_indices = [int(i) for i in np.argsort(diff)[-10:][::-1]]

    net_tp = counts["v2_only_tp"] - counts["v1_only_tp"]
    net_fp = counts["v2_only_fp"] - counts["v1_only_fp"]
    report = {
        "rows": len(X),
        "thresholds": {"v1": round(float(thr1), 6), "v2": round(float(thr2), 6)},
        "alerts": {"v1": int(a1.sum()), "v2": int(a2.sum())},
        "disagreements": int(disagree.sum()),
        "groups": {name: stats(mask) for name, mask in groups.items()},
        "net_detection_gain": net_tp,
        "net_fp_change": net_fp,
        "near_threshold_share": round(near_share, 4),
        "feature_lead_indices": lead_indices,
        "verdict": ("v2 wins: more true positives, no extra false positives"
                    if net_tp > 0 and net_fp <= 0 else
                    "trade-off: inspect groups before promoting"),
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
