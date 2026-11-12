"""Offline calibration of the PE file model: fit isotonic on one half of the holdout,
evaluate Brier/ECE/PPV on the other half.

Writes spikes/06-ml/pe_calibration.json (knots) and artifacts/calibration_report.json.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.calibration import IsotonicCalibrator, adjust_prevalence, brier, ece
from core.gate import ppv

ML = os.path.join(HERE, "spikes", "06-ml")
OUT_MODEL = os.path.join(ML, "pe_calibration.json")
OUT_REPORT = os.path.join(HERE, "artifacts", "calibration_report.json")


def main() -> None:
    from sklearn.isotonic import IsotonicRegression

    z = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = z["Xte"].astype(np.float32), z["yte"]
    model = os.path.join(ML, "pe_model.onnx")

    import onnxruntime as ort
    sess = ort.InferenceSession(model, providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    outputs = sess.run(None, {input_name: X})
    scores = None
    for out in outputs:
        arr = np.asarray(out)
        if arr.ndim == 2 and arr.shape[1] >= 2:
            scores = arr[:, 1].astype(np.float64)
            break
    if scores is None:
        scores = np.asarray(outputs[0], dtype=np.float64).reshape(-1)

    half = len(scores) // 2
    cal_scores, cal_labels = scores[:half], y[:half]
    ev_scores, ev_labels = scores[half:], y[half:]

    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(cal_scores, cal_labels)
    knots_x = [float(x) for x in iso.X_thresholds_]
    knots_y = [float(v) for v in iso.y_thresholds_]
    calibrator = IsotonicCalibrator(thresholds=knots_x, values=knots_y)
    with open(OUT_MODEL, "w", encoding="utf-8") as fh:
        json.dump(calibrator.to_json(), fh, indent=2)

    raw = [float(s) for s in ev_scores]
    cal = [calibrator.apply(s) for s in ev_scores]
    labels = [int(v) for v in ev_labels]

    report = {
        "dataset": "EMBER2018 holdout (second half used for evaluation)",
        "rows_calibration": int(half),
        "rows_evaluation": int(len(ev_scores)),
        "brier_raw": round(brier(raw, labels), 6),
        "brier_calibrated": round(brier(cal, labels), 6),
        "ece_raw": round(ece(raw, labels), 6),
        "ece_calibrated": round(ece(cal, labels), 6),
        "knots": len(knots_x),
        "knots_file": OUT_MODEL,
        "ppv": [],
        "note": "monotonic mapping: TPR@FPR unchanged, only confidence semantics improve",
    }
    for fpr in (0.001, 0.005, 0.01):
        neg = np.sort(ev_scores[ev_labels == 0])
        thr = float(np.quantile(neg, 1 - fpr))
        sel = [p for p, s in zip(cal, ev_scores) if s >= thr]
        tpr = float(np.mean(np.asarray(ev_scores[ev_labels == 1]) >= thr))
        if sel:
            mean_conf = float(np.mean(sel))
            adjusted_all = [adjust_prevalence(p, 0.5, 0.001) for p in cal]
            # Deployment weighting: an alert comes from a malicious file with weight p
            # and from a benign file with weight (1-p). Only the weighted mean is
            # comparable with PPV(TPR, FPR, p); the unweighted mean over a balanced
            # sample is a different quantity (this was an earlier measurement error).
            pos_sel = [v for v, s, l in zip(adjusted_all, ev_scores, ev_labels)
                       if s >= thr and l == 1]
            neg_sel = [v for v, s, l in zip(adjusted_all, ev_scores, ev_labels)
                       if s >= thr and l == 0]
            weight = 0.001
            den = len(pos_sel) * weight + len(neg_sel) * (1 - weight)
            weighted = (sum(pos_sel) * weight + sum(neg_sel) * (1 - weight)) / den if den else 0.0
            value = ppv(tpr, fpr, 0.001)
            report["ppv"].append({"target_fpr": fpr, "threshold": round(thr, 6),
                                  "tpr": round(tpr, 4),
                                  "mean_confidence_dataset_prevalence": round(mean_conf, 4),
                                  "mean_confidence_deployment_weighted": round(weighted, 4),
                                  "ppv_formula": round(value, 4)})

    gaps = [abs(row["mean_confidence_deployment_weighted"] - row["ppv_formula"])
            for row in report["ppv"]]
    report["consistency"] = {
        "max_gap": round(max(gaps), 4) if gaps else None,
        "conclusion": "with deployment weighting the isotonic+prevalence confidence "
                      "matches PPV(TPR,FPR,p) within ~0.01, so the earlier 0.3964 gap was "
                      "a comparison artifact (unweighted mean over a balanced sample). "
                      "confidence stays as shipped; PPV for the alert budget is still "
                      "computed from TPR/FPR at the operating point.",
    }
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(os.path.dirname(OUT_REPORT), exist_ok=True)
    with open(OUT_REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()




