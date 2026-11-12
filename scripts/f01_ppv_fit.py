"""F01: fit the tail-PPV confidence table for the PE v2 model and measure the gap.

Before (isotonic on a balanced set + prevalence adjustment): mean confidence of
alerts 0.4749 vs measured precision 0.0785 -> gap 0.3964.
After (tail PPV at the deployment prevalence): the gap should collapse, because the
number *is* the precision of the alert tail at that threshold.

Writes spikes/06-ml/pe_v2_ppv.json and artifacts/f01_confidence.json.
"""

from __future__ import annotations

import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.calibration import IsotonicCalibrator, adjust_prevalence, ece
from core.ml import fpr_threshold
from core.ppv_calibration import fit_ppv_table

ML = os.path.join(HERE, "spikes", "06-ml")
OUT_MODEL = os.path.join(ML, "pe_v2_ppv.json")
OUT_REPORT = os.path.join(HERE, "artifacts", "f01_confidence.json")
PREVALENCE = 0.001
TARGET_FPR = 0.01


def scores() -> tuple[np.ndarray, np.ndarray]:
    import onnxruntime as ort
    cache = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = cache["Xte"].astype(np.float32), cache["yte"]
    sess = ort.InferenceSession(os.path.join(ML, "pe_v2_model.onnx"),
                                providers=["CPUExecutionProvider"])
    out = sess.run(None, {sess.get_inputs()[0].name: X})
    proba = next(np.asarray(o)[:, 1].astype(np.float64) for o in out
                 if np.asarray(o).ndim == 2 and np.asarray(o).shape[1] >= 2)
    return proba, y


def main() -> None:
    s, y = scores()
    half = len(s) // 2
    cal_s, cal_y = list(s[:half]), [int(v) for v in y[:half]]
    ev_s, ev_y = s[half:], [int(v) for v in y[half:]]

    table = fit_ppv_table(cal_s, cal_y, prevalence=PREVALENCE, bins=32)
    with open(OUT_MODEL, "w", encoding="utf-8") as fh:
        json.dump(table.to_json(), fh, indent=2)

    # operating point on evaluation data: 1 % FPR on benign
    thr = fpr_threshold([float(v) for v, label in zip(ev_s, ev_y) if label == 0], TARGET_FPR)
    alerts = [(float(sc), label) for sc, label in zip(ev_s, ev_y) if sc >= thr]
    pos_alerts = [sc for sc, label in alerts if label == 1]
    neg_alerts = [sc for sc, label in alerts if label == 0]

    # Deployment-weighted comparison. At prevalence p an alert comes from a malicious
    # file with weight p and from a benign file with weight (1-p), so the weighted mean
    # confidence must match PPV(TPR, FPR, p) measured on the same evaluation rows.
    p = PREVALENCE
    n_neg_eval = sum(1 for label in ev_y if label == 0)
    n_pos_eval = sum(1 for label in ev_y if label == 1)
    tpr = len(pos_alerts) / max(1, n_pos_eval)
    fpr = len(neg_alerts) / max(1, n_neg_eval)
    precision_deploy = (tpr * p) / (tpr * p + fpr * (1 - p))

    def weighted_mean(values_pos: list[float], values_neg: list[float]) -> float:
        num = sum(values_pos) * p + sum(values_neg) * (1 - p)
        den = len(values_pos) * p + len(values_neg) * (1 - p)
        return num / den if den else 0.0

    iso = IsotonicCalibrator.load(os.path.join(ML, "pe_v2_calibration.json"))
    conf_iso_pos = [adjust_prevalence(iso.apply(sc), 0.5, p) for sc in pos_alerts]
    conf_iso_neg = [adjust_prevalence(iso.apply(sc), 0.5, p) for sc in neg_alerts]
    mean_iso = weighted_mean(conf_iso_pos, conf_iso_neg)

    conf_ppv_pos = [table.apply(sc) for sc in pos_alerts]
    conf_ppv_neg = [table.apply(sc) for sc in neg_alerts]
    mean_ppv = weighted_mean(conf_ppv_pos, conf_ppv_neg)

    # stability check: does the table fitted on the first half reproduce the second
    # half's deployment posterior at the same knots?
    drift = []
    for knot in table.edges[1:-1:8]:
        tpr_k = sum(1 for sc in pos_alerts if sc >= knot) / max(1, n_pos_eval)
        fpr_k = sum(1 for sc in neg_alerts if sc >= knot) / max(1, n_neg_eval)
        if tpr_k * p + fpr_k * (1 - p) == 0:
            continue
        empirical = (tpr_k * p) / (tpr_k * p + fpr_k * (1 - p))
        drift.append(abs(empirical - table.apply(knot)))

    report = {
        "model": "aidf-pe-ember-v2",
        "prevalence": p,
        "target_fpr": TARGET_FPR,
        "threshold": round(float(thr), 6),
        "alerts_balanced_sample": len(alerts),
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 5),
        "precision_at_deployment": round(precision_deploy, 4),
        "mean_confidence_isotonic": round(mean_iso, 4),
        "gap_isotonic": round(abs(mean_iso - precision_deploy), 4),
        "mean_confidence_tail_ppv": round(mean_ppv, 4),
        "gap_tail_ppv": round(abs(mean_ppv - precision_deploy), 4),
        "bands": len(table.values),
        "half_to_half_drift_max": round(max(drift), 4) if drift else None,
        "half_to_half_drift_p95": round(sorted(drift)[int(len(drift) * 0.95)] if drift else 0, 4),
        "confidence_source": "bin_ppv",
        "note": "prevalence-weighted mean confidence vs PPV(TPR,FPR,p) on the same rows",
    }
    with open(OUT_REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

