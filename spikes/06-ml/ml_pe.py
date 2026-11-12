"""Spike 6: PE file-model TPR@FPR on EMBER2018 holdout shards (features only, no executables).

Method:
  * benign train: ember2018_train_1..4.json      (all-benign shards in this mirror)
  * malicious train: ember2018_train_45/60/70/75/80.json (mixed shards)
  * test (holdout, untouched): ember2018_test_1..5.json (50k, ~50/50)
  * model: LightGBM binary classifier, offline training (runtime does inference only)
Reports TPR at fixed FPR with absolute TP/FP counts, Wilson CI, and single-row latency.
"""
import json, os, sys, time, glob, math
import numpy as np

HERE = os.path.dirname(__file__)
DATA = os.path.join(HERE, "..", "artifacts", "data")
OUT = os.path.join(HERE, "ml_pe_result.json")

BENIGN = ["ember2018_train_1.json", "ember2018_train_2.json", "ember2018_train_3.json", "ember2018_train_4.json"]
MALICIOUS = ["ember2018_train_45.json", "ember2018_train_60.json", "ember2018_train_70.json",
             "ember2018_train_75.json", "ember2018_train_80.json"]
TEST = [f"ember2018_test_{i}.json" for i in range(1, 6)]


def load(files):
    xs, ys = [], []
    used = []
    for name in files:
        p = os.path.join(DATA, name)
        if not os.path.exists(p):
            continue
        with open(p) as fh:
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
    return ((c - r) / d, (c + r) / d)


def main():
    t0 = time.time()
    cache = os.path.join(HERE, "pe_cache.npz")
    if os.path.exists(cache):
        z = np.load(cache)
        Xtr, ytr, Xte, yte = z["Xtr"], z["ytr"], z["Xte"], z["yte"]
        fb = fm = ft = ["<cached>"]
    else:
        Xb, yb, fb = load(BENIGN)
        Xm, ym, fm = load(MALICIOUS)
        Xtr = np.vstack([Xb, Xm]); ytr = np.concatenate([yb, ym])
        Xte, yte, ft = load(TEST)
        np.savez_compressed(cache, Xtr=Xtr, ytr=ytr, Xte=Xte, yte=yte)
    load_s = time.time() - t0
    print(f"train={Xtr.shape} benign={int((ytr == 0).sum())} mal={int(ytr.sum())} from={fb + fm}")
    print(f"test={Xte.shape} pos={int(yte.sum())} files={ft} load_s={load_s:.1f}")

    import lightgbm as lgb
    params = dict(objective="binary", metric="auc", learning_rate=0.08, num_leaves=64,
                  min_data_in_leaf=40, feature_fraction=0.5, bagging_fraction=0.8,
                  bagging_freq=1, verbose=-1, num_threads=8, seed=1337,
                  scale_pos_weight=float((ytr == 0).sum()) / max(1, int(ytr.sum())))
    t0 = time.time()
    booster = lgb.train(params, lgb.Dataset(Xtr, label=ytr), num_boost_round=400)
    train_s = time.time() - t0
    best = booster.best_iteration or booster.current_iteration()

    t0 = time.time()
    scores = booster.predict(Xte, num_iteration=best)
    predict_s = time.time() - t0
    from sklearn.metrics import roc_auc_score

    neg, pos = scores[yte == 0], scores[yte == 1]
    res = {"dataset": "EMBER2018 (vectorized features; test shards never trained on)",
           "benign_train_files": fb, "malicious_train_files": fm, "test_files": ft,
           "train_n": int(Xtr.shape[0]), "train_mal": int(ytr.sum()),
           "test_n": int(Xte.shape[0]), "test_pos": int(yte.sum()), "test_neg": int((yte == 0).sum()),
           "dims": int(Xtr.shape[1]), "trees": int(best),
           "load_s": round(load_s, 1), "train_s": round(train_s, 1), "predict_50k_s": round(predict_s, 2),
           "auc": round(float(roc_auc_score(yte, scores)), 5), "operating_points": []}

    for fpr_t in (0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05):
        thr = float(np.quantile(neg, 1 - fpr_t))
        tp, fp = int((pos >= thr).sum()), int((neg >= thr).sum())
        lo, hi = wilson(tp, len(pos))
        res["operating_points"].append({
            "target_fpr": fpr_t, "threshold": round(thr, 6), "tp": tp, "fp": fp,
            "fpr_measured": round(fp / len(neg), 5), "tpr": round(tp / len(pos), 5),
            "tpr_ci95": [round(lo, 4), round(hi, 4)],
            "fpr_ci95": [round(v, 5) for v in wilson(fp, len(neg))],
        })

    row = Xte[:1]
    for _ in range(50):
        booster.predict(row)
    lat = []
    for _ in range(300):
        t = time.perf_counter(); booster.predict(row); lat.append((time.perf_counter() - t) * 1000)
    lat.sort()
    res["latency_single_row_ms"] = {"p50": round(lat[150], 3), "p95": round(lat[int(len(lat) * .95)], 3), "max": round(lat[-1], 3)}

    with open(OUT, "w") as fh:
        json.dump(res, fh, indent=2)

    # LightGBM's C++ writer cannot handle the non-ASCII workspace path: save to temp, then copy.
    import tempfile, shutil
    tmp_model = os.path.join(tempfile.gettempdir(), "pe_model.txt")
    booster.save_model(tmp_model)
    shutil.copyfile(tmp_model, os.path.join(HERE, "pe_model.txt"))
    res["model_file_mb"] = round(os.path.getsize(os.path.join(HERE, "pe_model.txt")) / 1e6, 2)
    with open(OUT, "w") as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps({k: v for k, v in res.items() if k != "operating_points"}, indent=2))
    for op in res["operating_points"]:
        print(f"FPR<={op['target_fpr']*100:.2f}% -> measured FPR={op['fpr_measured']*100:.3f}% TPR={op['tpr']:.3f} (TP={op['tp']} FP={op['fp']})")


if __name__ == "__main__":
    main()
