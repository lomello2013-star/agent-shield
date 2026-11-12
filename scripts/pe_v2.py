"""E7 attempt v2: train on an expanded shard set with stronger parameters.

Question: does more data / a stronger model move TPR at very low FPR
(0.05 %, the E7 target), or is the static-feature ceiling real?

Writes artifacts/pe_v2_report.json. Offline only вЂ” no on-device training.
"""

from __future__ import annotations

import glob
import json
import math
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "spikes", "artifacts", "data")
OUT = os.path.join(HERE, "artifacts", "pe_v2_report.json")
CACHE = os.path.join(HERE, "spikes", "06-ml", "pe_v2_cache.npz")

BENIGN = ["ember2018_train_1.json", "ember2018_train_2.json",
          "ember2018_train_3.json", "ember2018_train_4.json"]
MALICIOUS = ["ember2018_train_45.json", "ember2018_train_60.json",
             "ember2018_train_70.json", "ember2018_train_75.json",
             "ember2018_train_80.json", "ember2018_train_52.json",
             "ember2018_train_57.json", "ember2018_train_62.json",
             "ember2018_train_67.json", "ember2018_train_72.json",
             "ember2018_train_77.json"]
TEST = [f"ember2018_test_{i}.json" for i in range(1, 6)]


def load(files):
    xs, ys, used = [], [], []
    for name in files:
        path = os.path.join(DATA, name)
        if not os.path.exists(path):
            continue
        with open(path) as fh:
            arr = json.load(fh)
        for rec in arr:
            xs.append(rec["x"])
            ys.append(int(rec["y"]))
        used.append(name)
    return np.asarray(xs, dtype=np.float32), np.asarray(ys, dtype=np.int8), used


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(max(0.0, p * (1 - p) / n + z * z / (4 * n * n)))
    return (c - r) / d, (c + r) / d


def main() -> None:
    t0 = time.time()
    if os.path.exists(CACHE):
        z = np.load(CACHE)
        Xtr, ytr, Xte, yte = z["Xtr"], z["ytr"], z["Xte"], z["yte"]
        tr_used, te_used = ["<cached>"], ["<cached>"]
    else:
        Xb, yb, fb = load(BENIGN)
        Xm, ym, fm = load(MALICIOUS)
        Xtr = np.vstack([Xb, Xm]); ytr = np.concatenate([yb, ym])
        Xte, yte, te_used = load(TEST)
        np.savez_compressed(CACHE, Xtr=Xtr, ytr=ytr, Xte=Xte, yte=yte)
        tr_used = fb + fm
    print(f"train={Xtr.shape} mal={int(ytr.sum())} test={Xte.shape} pos={int(yte.sum())}", flush=True)

    import lightgbm as lgb
    params = dict(objective="binary", metric="auc", learning_rate=0.05,
                  num_leaves=96, min_data_in_leaf=30, feature_fraction=0.35,
                  bagging_fraction=0.8, bagging_freq=1, verbose=-1,
                  num_threads=8, seed=2026,
                  scale_pos_weight=float((ytr == 0).sum()) / max(1, int(ytr.sum())))
    t0 = time.time()
    booster = lgb.train(params, lgb.Dataset(Xtr, label=ytr), num_boost_round=700)
    train_s = time.time() - t0
    print(f"train_s={train_s:.1f}", flush=True)

    scores = booster.predict(Xte, num_iteration=booster.best_iteration or
                             booster.current_iteration())
    from sklearn.metrics import roc_auc_score
    neg, pos = scores[yte == 0], scores[yte == 1]
    report = {"train_n": int(Xtr.shape[0]), "train_mal": int(ytr.sum()),
              "test_n": int(Xte.shape[0]), "test_pos": int(yte.sum()),
              "auc": round(float(roc_auc_score(yte, scores)), 5),
              "train_s": round(train_s, 1), "trees": booster.current_iteration(),
              "operating_points": [],
              "baseline": {"tpr_at_fpr_0.05": 0.535, "tpr_at_fpr_0.1": 0.649,
                           "tpr_at_fpr_1.0": 0.854}}
    for fpr_t in (0.0005, 0.001, 0.005, 0.01):
        thr = float(np.quantile(neg, 1 - fpr_t))
        tp, fp = int((pos >= thr).sum()), int((neg >= thr).sum())
        lo, hi = wilson(tp, len(pos))
        report["operating_points"].append({
            "target_fpr": fpr_t, "threshold": round(thr, 6), "tp": tp, "fp": fp,
            "fpr_measured": round(fp / len(neg), 5), "tpr": round(tp / len(pos), 5),
            "tpr_ci95": [round(lo, 4), round(hi, 4)]})
    import shutil, tempfile
    tmp_model = os.path.join(tempfile.gettempdir(), "pe_v2_model.txt")
    booster.save_model(tmp_model)
    shutil.copyfile(tmp_model, os.path.join(HERE, "spikes", "06-ml", "pe_v2_model.txt"))
    report["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

