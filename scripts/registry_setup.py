"""Register candidate models and run the champion/challenger comparison.

Honesty note: the registry requires a human (operator=True) to crown a champion.
This script therefore registers both models as **challengers** and leaves the
champion slot empty; the comparison report argues for a promotion that a human
must actually perform.

Writes models/registry.json and artifacts/challenger_report.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.model_registry import ModelEntry, ModelRegistry
from core.modelpack import private_key_from_hex, sign_pack
from core.ml import OnnxModel, fpr_threshold

ML = os.path.join(HERE, "spikes", "06-ml")
REG_ROOT = os.path.join(HERE, "models")
KEYS = os.path.join(HERE, "secrets", "dev_keys.json")
OUT = os.path.join(HERE, "artifacts", "challenger_report.json")


def load_keys() -> tuple[str, str]:
    with open(KEYS, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["private_hex"], data["public_hex"]


def resign_pack(pack_path: str, priv_hex: str) -> None:
    """Re-sign a dev pack with the registry's dev key (same canonical fields)."""
    with open(pack_path, encoding="utf-8") as fh:
        pack = json.load(fh)
    body = {k: v for k, v in pack.items() if k != "signature"}
    pack["signature"] = sign_pack(body, private_key_from_hex(priv_hex))
    with open(pack_path, "w", encoding="utf-8") as fh:
        json.dump(pack, fh, indent=2)


def entry_for(model_id: str, version: str, onnx: str, pack: str,
              metrics: dict) -> ModelEntry:
    return ModelEntry(model_id=model_id, version=version, role="challenger",
                      artifact=onnx, pack_path=pack, metrics=metrics)


def compare() -> dict:
    cache = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = cache["Xte"][:5000].astype(np.float32), cache["yte"][:5000]
    v1 = OnnxModel(os.path.join(ML, "pe_model.onnx"))
    v2 = OnnxModel(os.path.join(ML, "pe_v2_model.onnx"))
    t0 = time.perf_counter()
    s1, s2 = v1.predict(X), v2.predict(X)
    elapsed = time.perf_counter() - t0
    neg1, neg2 = s1[y == 0], s2[y == 0]
    pos1, pos2 = s1[y == 1], s2[y == 1]

    def point(scores, neg, pos, fpr_target=0.01):
        thr = fpr_threshold(list(neg), fpr_target)
        tp = int((pos >= thr).sum()); fp = int((neg >= thr).sum())
        return {"threshold": round(float(thr), 6), "tp": tp, "fp": fp,
                "tpr": round(tp / len(pos), 4), "fpr": round(fp / len(neg), 5)}

    p1, p2 = point(s1, neg1, pos1), point(s2, neg2, pos2)
    # agreement at each model's own 1 % FPR threshold
    a1 = s1 >= p1["threshold"]; a2 = s2 >= p2["threshold"]
    agree = int((a1 == a2).sum())
    lat1 = [v1.predict_one(list(row))[1] for row in X[:200]]
    lat2 = [v2.predict_one(list(row))[1] for row in X[:200]]
    lat1_med = round(statistics.median(lat1), 3)
    lat2_med = round(statistics.median(lat2), 3)
    promote = p2["tpr"] > p1["tpr"] and lat2_med <= lat1_med * 2
    return {
        "rows": len(X),
        "v1": p1, "v2": p2,
        "v2_minus_v1_tpr_pp": round(100 * (p2["tpr"] - p1["tpr"]), 2),
        "alert_agreement_pct": round(100 * agree / len(X), 2),
        "disagreements": int(len(X) - agree),
        "latency_ms_p50_v1": lat1_med,
        "latency_ms_p50_v2": lat2_med,
        "scoring_5k_s": round(elapsed, 3),
        "recommendation": "promote v2" if promote else "keep v1",
    }


def main() -> None:
    priv_hex, pub_hex = load_keys()
    for pack in (os.path.join(ML, "pe_pack.json"), os.path.join(ML, "pe_v2_pack.json")):
        resign_pack(pack, priv_hex)

    registry = ModelRegistry(REG_ROOT, pub_hex)
    registered = []
    for model_id, version, onnx_name, pack_name, metrics in (
        ("aidf-pe-ember", "1.0.0", "pe_model.onnx", "pe_pack.json",
         {"tpr_at_fpr_1pct": 0.854, "auc": 0.9895}),
        ("aidf-pe-ember-v2", "2.0.0", "pe_v2_model.onnx", "pe_v2_pack.json",
         {"tpr_at_fpr_1pct": 0.9014, "tpr_at_fpr_0.05pct": 0.6724, "auc": 0.99277}),
    ):
        entry = entry_for(model_id, version, os.path.join(ML, onnx_name),
                          os.path.join(ML, pack_name), metrics)
        try:
            registry.register(entry)
            registered.append(f"{model_id}@{version}")
        except Exception as exc:                     # already registered on re-run
            registered.append(f"{model_id}@{version} (exists: {type(exc).__name__})")

    report = compare()
    report["registry"] = {
        "models": [f"{e.model_id}@{e.version}:{e.role}" for e in registry.entries],
        "champion": registry.champion().model_id if registry.champion() else None,
        "note": "champion slot intentionally empty: promotion requires a human "
                "(operator=True); an agent may register and compare only",
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

