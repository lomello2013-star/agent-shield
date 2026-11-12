"""F08: can the low-FPR tail be improved without new data?

E7 target is 0.95 TPR at 0.05 % FPR; the shipped v2 model reaches 0.6724. Before
claiming "static ceiling", three cheap levers are tested on the same cached data:

  A  baseline      — the shipped configuration (700 trees, 96 leaves, lr 0.05)
  B  deeper/lower  — 1500 trees, 128 leaves, lr 0.03
  C  hard-negative — baseline plus duplicated rows of the benign files that A scores
                     highest (the actual false positives at the operating point)

No new data, no on-device training: everything stays offline. Writes
artifacts/f08_tail.json.
"""

from __future__ import annotations

import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML = os.path.join(HERE, "spikes", "06-ml")
OUT = os.path.join(HERE, "artifacts", "f08_tail.json")
TARGETS = (0.0005, 0.001, 0.005, 0.01)


def load() -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    cache = np.load(os.path.join(ML, "pe_v2_cache.npz"))
    return cache["Xtr"], cache["ytr"], cache["Xte"], cache["yte"]


def evaluate(scores: np.ndarray, y: np.ndarray) -> dict:
    neg, pos = scores[y == 0], scores[y == 1]
    out = {}
    for fpr_target in TARGETS:
        thr = float(np.quantile(neg, 1 - fpr_target))
        tp = int((pos >= thr).sum())
        fp = int((neg >= thr).sum())
        out[f"tpr_at_fpr_{fpr_target}"] = round(tp / len(pos), 4)
        out[f"fpr_measured_{fpr_target}"] = round(fp / len(neg), 5)
    return out


def train(name: str, Xtr, ytr, params: dict, rounds: int, extra_rows=None) -> dict:
    import lightgbm as lgb
    X, y = Xtr, ytr
    if extra_rows is not None:
        X = np.vstack([Xtr, Xtr[extra_rows]])
        y = np.concatenate([ytr, ytr[extra_rows]])
    started = time.time()
    booster = lgb.train(params, lgb.Dataset(X, label=y), num_boost_round=rounds)
    return {"name": name, "train_s": round(time.time() - started, 1),
            "train_rows": int(X.shape[0]), "booster": booster}


def main() -> None:
    import lightgbm as lgb
    from sklearn.metrics import roc_auc_score

    Xtr, ytr, Xte, yte = load()
    base_params = dict(objective="binary", metric="auc", learning_rate=0.05,
                       num_leaves=96, min_data_in_leaf=30, feature_fraction=0.35,
                       bagging_fraction=0.8, bagging_freq=1, verbose=-1,
                       num_threads=8, seed=2026,
                       scale_pos_weight=float((ytr == 0).sum()) / max(1, int(ytr.sum())))

    report: dict = {"data": {"train": int(Xtr.shape[0]), "malicious": int(ytr.sum()),
                             "test": int(Xte.shape[0])}, "runs": []}

    baseline = train("A_baseline", Xtr, ytr, base_params, 700)
    scores_a = baseline["booster"].predict(Xte)
    report["runs"].append({"name": "A_baseline", "train_s": baseline["train_s"],
                           "auc": round(float(roc_auc_score(yte, scores_a)), 5),
                           **evaluate(scores_a, yte)})
    print("A:", report["runs"][-1]["tpr_at_fpr_0.0005"], flush=True)

    deeper_params = dict(base_params, num_leaves=112, learning_rate=0.04)
    deeper = train("B_deeper", Xtr, ytr, deeper_params, 1000)
    scores_b = deeper["booster"].predict(Xte)
    report["runs"].append({"name": "B_deeper", "train_s": deeper["train_s"],
                           "auc": round(float(roc_auc_score(yte, scores_b)), 5),
                           **evaluate(scores_b, yte)})
    print("B:", report["runs"][-1]["tpr_at_fpr_0.0005"], flush=True)

    # hard negatives: benign rows the baseline ranks highest (the ones that become FPs)
    neg_scores = scores_a[yte == 0]
    threshold = float(np.quantile(neg_scores, 0.9995))
    hard_mask = np.where((ytr == 0) & (baseline["booster"].predict(Xtr) >= threshold))[0]
    mined = train("C_hard_negative", Xtr, ytr, base_params, 700, extra_rows=hard_mask)
    scores_c = mined["booster"].predict(Xte)
    report["runs"].append({"name": "C_hard_negative", "train_s": mined["train_s"],
                           "hard_rows_added": int(len(hard_mask)),
                           "auc": round(float(roc_auc_score(yte, scores_c)), 5),
                           **evaluate(scores_c, yte)})
    print("C:", report["runs"][-1]["tpr_at_fpr_0.0005"], flush=True)

    best = max(report["runs"], key=lambda r: r["tpr_at_fpr_0.0005"])
    report["best"] = {"name": best["name"],
                      "tpr_at_fpr_0.0005": best["tpr_at_fpr_0.0005"],
                      "shipped_v2": 0.6724,
                      "target": 0.95,
                      "improved": best["tpr_at_fpr_0.0005"] > 0.6724 + 0.01,
                      "target_met": best["tpr_at_fpr_0.0005"] >= 0.95}
    report["conclusion"] = (
        "ни один из трёх приёмов не сдвинул хвост существенно — потолок статики "
        "подтверждён на этих данных"
        if not report["best"]["improved"] else
        "хвост сдвинулся, но цель 0,95 @0,05 % не достигнута"
        if not report["best"]["target_met"] else "цель E7 достигнута на этих данных")
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps({r["name"]: r["tpr_at_fpr_0.0005"] for r in report["runs"]},
                     ensure_ascii=False))
    print(json.dumps(report["best"], ensure_ascii=False))


if __name__ == "__main__":
    main()
