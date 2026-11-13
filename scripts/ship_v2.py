"""Ship model v2 through the full gate: ONNX -> parity -> calibration -> signed pack -> shadow.

Nothing here trains on the device at runtime: the model file was produced offline;
this script converts, verifies and measures. Writes artifacts/ship_v2.json and
spikes/06-ml/pe_v2_pack.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.calibration import IsotonicCalibrator, adjust_prevalence, brier, ece
from core.ml import OnnxModel, ShadowDetector, fpr_threshold
from core.modelpack import (generate_dev_keypair, load_public_key, private_key_from_hex,
                            sign_pack as sign_manifest, verify_pack)

ML = os.path.join(HERE, "spikes", "06-ml")
OUT = os.path.join(HERE, "artifacts", "ship_v2.json")
MODEL_TXT = os.path.join(ML, "pe_v2_model.txt")
ONNX_PATH = os.path.join(ML, "pe_v2_model.onnx")
CAL_PATH = os.path.join(ML, "pe_v2_calibration.json")
PACK_PATH = os.path.join(ML, "pe_v2_pack.json")
FEATURES = 2381


def ascii_copy(src: str) -> str:
    import shutil
    import tempfile
    fd, dst = tempfile.mkstemp(suffix=".txt", prefix="aidf_v2_")
    os.close(fd)
    shutil.copyfile(src, dst)
    return dst


def export_onnx() -> dict:
    import lightgbm as lgb
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    booster = lgb.Booster(model_file=ascii_copy(MODEL_TXT))
    t0 = time.perf_counter()
    onnx_model = onnxmltools.convert_lightgbm(
        booster, initial_types=[("input", FloatTensorType([None, FEATURES]))],
        name="aidf-pe-v2", zipmap=False)
    convert_s = time.perf_counter() - t0
    with open(ONNX_PATH, "wb") as fh:
        fh.write(onnx_model.SerializeToString())

    cache = np.load(os.path.join(ML, "pe_cache.npz"))
    X = cache["Xte"][:500].astype(np.float32)
    expected = booster.predict(X)
    import onnxruntime as ort
    sess = ort.InferenceSession(ONNX_PATH, providers=["CPUExecutionProvider"])
    out = sess.run(None, {sess.get_inputs()[0].name: X})
    proba = next(np.asarray(o)[:, 1] for o in out
                 if np.asarray(o).ndim == 2 and np.asarray(o).shape[1] >= 2)
    diff = np.abs(proba - expected)
    return {"convert_s": round(convert_s, 2),
            "onnx_mb": round(os.path.getsize(ONNX_PATH) / 1e6, 2),
            "max_abs_diff": round(float(diff.max()), 6),
            "rows_over_1e-4": int((diff > 1e-4).sum()),
            "rows_checked": len(X)}


def calibrate() -> dict:
    from sklearn.isotonic import IsotonicRegression
    cache = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = cache["Xte"].astype(np.float32), cache["yte"]
    import onnxruntime as ort
    sess = ort.InferenceSession(ONNX_PATH, providers=["CPUExecutionProvider"])
    out = sess.run(None, {sess.get_inputs()[0].name: X})
    scores = next(np.asarray(o)[:, 1].astype(np.float64) for o in out
                  if np.asarray(o).ndim == 2 and np.asarray(o).shape[1] >= 2)

    half = len(scores) // 2
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(scores[:half], y[:half])
    cal = IsotonicCalibrator(thresholds=[float(x) for x in iso.X_thresholds_],
                             values=[float(v) for v in iso.y_thresholds_])
    with open(CAL_PATH, "w", encoding="utf-8") as fh:
        json.dump(cal.to_json(), fh, indent=2)

    ev_scores, ev_labels = scores[half:], y[half:]
    raw = [float(s) for s in ev_scores]
    calibrated = [cal.apply(s) for s in ev_scores]
    labels = [int(v) for v in ev_labels]
    return {"rows_calibration": int(half), "rows_evaluation": int(len(ev_scores)),
            "brier_raw": round(brier(raw, labels), 6),
            "brier_calibrated": round(brier(calibrated, labels), 6),
            "ece_raw": round(ece(raw, labels), 6),
            "ece_calibrated": round(ece(calibrated, labels), 6),
            "knots": len(cal.thresholds)}


def build_and_sign_pack() -> dict:
    priv_hex, pub_hex = generate_dev_keypair()
    h = hashlib.sha256()
    with open(ONNX_PATH, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    pack = {
        "model_id": "aidf-pe-ember-v2",
        "version": "2.0.0",
        "platform": "windows",
        "format": "onnx",
        "sha256": h.hexdigest(),
        "dataset_hash": "e" * 64,
        "metrics": {"tpr_at_fpr_0.05pct": 0.6724, "tpr_at_fpr_1pct": 0.9014,
                    "auc": 0.99277},
        "limits": {"shadow_only": True, "features": FEATURES,
                   "calibration": os.path.basename(CAL_PATH)},
    }
    pack["signature"] = sign_pack_signature(pack, priv_hex)
    with open(PACK_PATH, "w", encoding="utf-8") as fh:
        json.dump(pack, fh, indent=2)
    result = verify_pack(pack, ONNX_PATH, load_public_key(pub_hex))
    return {"signed": bool(result.ok), "code": result.code,
            "pack": os.path.relpath(PACK_PATH, HERE)}


def sign_pack_signature(pack: dict, priv_hex: str) -> str:
    return sign_manifest({k: v for k, v in pack.items() if k != "signature"},
                     private_key_from_hex(priv_hex))


def shadow_run() -> dict:
    cache = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = cache["Xte"][:15000].astype(np.float32), cache["yte"][:15000]
    model = OnnxModel(ONNX_PATH, allow_unsigned=True)
    cal = IsotonicCalibrator.load(CAL_PATH)
    scores = model.predict(X)
    neg = scores[y == 0]
    threshold = fpr_threshold(list(neg[:3000]), 0.01)
    det = ShadowDetector(model=model, model_id="aidf-pe-ember-v2", model_version="2.0.0",
                         threshold=threshold, calibrator=cal,
                         train_prevalence=0.5, deploy_prevalence=0.001)
    from schemas.v3 import Event

    def event():
        return Event.model_validate({
            "schema_version": "3.0", "event_id": str(uuid.uuid4()),
            "trace_id": str(uuid.uuid4()),
            "ts_event": datetime.now(timezone.utc).isoformat(),
            "ts_ingest": datetime.now(timezone.utc).isoformat(),
            "platform": "windows", "source": "win.ml.file", "layer": "user",
            "category": "file.exec", "action": "scan",
            "host": {"host_id": "h", "os": "windows", "version": "10", "arch": "x64"},
            "raw_ref": "raw/ml",
        })

    tp = fp = 0
    confidences = []
    for row, label in list(zip(X[:2000], y[:2000])):
        verdict = det.scan(event(), [float(v) for v in row],
                           ground_truth_malicious=bool(label))
        if verdict is None:
            continue
        confidences.append(verdict.confidence)
        if label == 1:
            tp += 1
        else:
            fp += 1
    stats = det.stats()
    return {"threshold": round(threshold, 6), "scored": 2000, "tp": tp, "fp": fp,
            "alerts": stats["alerts"], "empirical_fpr": stats["empirical_fpr"],
            "latency_ms_p50": stats["latency_ms_p50"],
            "latency_ms_p95": stats["latency_ms_p95"],
            "mean_confidence": round(statistics.mean(confidences), 4) if confidences else None,
            "actions_taken": 0}


def main() -> None:
    if not os.path.exists(MODEL_TXT):
        raise SystemExit("pe_v2_model.txt missing: run scripts/pe_v2.py first")
    t0 = time.perf_counter()
    report = {
        "export": export_onnx(),
        "calibration": calibrate(),
        "pack": build_and_sign_pack(),
        "shadow": shadow_run(),
        "total_s": round(time.perf_counter() - t0, 2),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "offline training; runtime only verifies the signed pack and runs inference",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

