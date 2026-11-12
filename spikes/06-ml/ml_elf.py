"""Spike 6: ELF file-model TPR@FPR on EMBER2024 ELF data (fresh: Sep-Nov 2024 submissions).

Method:
  * train: ELF_train (52 weekly jsonl shards from EMBER2024)
  * test : ELF_test  (12 weekly jsonl shards, separate weeks)
  * features built from thrember JSON: 256-bin byte histogram, 256-bin byte entropy,
    string/general statistics, string-count dictionary (fixed key list)
  * model: LightGBM binary classifier (offline training; runtime inference only)
Reports TPR at fixed FPR with absolute counts + Wilson CI and "freshness" of test weeks.
"""
import json, os, sys, time, glob, math
import numpy as np

HERE = os.path.dirname(__file__)
DATA = os.path.join(HERE, "..", "artifacts", "data")
OUT = os.path.join(HERE, "ml_elf_result.json")

STRING_KEYS = ["printables", "paths", "urls", "registry", "MZ", "mz", "dos", "names",
               "PE", "pe", "macho", "elf", "total", "numstrings"]


def features(rec):
    hist = rec.get("histogram") or []
    ent = rec.get("byteentropy") or []
    st = rec.get("strings") or {}
    gen = rec.get("general") or {}
    sc = st.get("string_counts") or {}
    f = np.zeros(256 + 256 + 4 + 3 + len(STRING_KEYS), dtype=np.float32)
    h = np.asarray(hist[:256], dtype=np.float32)
    f[:len(h)] = h
    e = np.asarray(ent[:256], dtype=np.float32)
    f[256:256 + len(e)] = e
    base = 512
    f[base + 0] = math.log1p(st.get("numstrings", 0) or 0)
    f[base + 1] = st.get("avlength", 0) or 0
    f[base + 2] = st.get("printables", 0) or 0
    f[base + 3] = st.get("entropy", 0) or 0
    f[base + 4] = math.log1p(gen.get("size", 0) or 0)
    f[base + 5] = gen.get("entropy", 0) or 0
    f[base + 6] = 1.0 if gen.get("is_pe") else 0.0
    for i, k in enumerate(STRING_KEYS):
        f[base + 7 + i] = math.log1p(sc.get(k, 0) or 0)
    return f


def load_dir(pattern):
    X, y, weeks = [], [], []
    files = sorted(glob.glob(os.path.join(DATA, pattern)))
    for fp in files:
        with open(fp) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                X.append(features(r))
                y.append(int(r.get("label", 0)))
                weeks.append(r.get("week_id"))
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int8), weeks, len(files)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def main():
    t0 = time.time()
    Xtr, ytr, wtr, ntr_f = load_dir("elf_train/*.jsonl")
    Xte, yte, wte, nte_f = load_dir("elf_test/*.jsonl")
    load_s = time.time() - t0
    print(f"train={Xtr.shape} pos={int(ytr.sum())} shards={ntr_f} | test={Xte.shape} pos={int(yte.sum())} shards={nte_f} load_s={load_s:.1f}")

    import lightgbm as lgb
    params = dict(objective="binary", metric="auc", learning_rate=0.08, num_leaves=48,
                  min_data_in_leaf=20, feature_fraction=0.6, bagging_fraction=0.8,
                  bagging_freq=1, verbose=-1, num_threads=8, seed=1337)
    t0 = time.time()
    booster = lgb.train(params, lgb.Dataset(Xtr, label=ytr), num_boost_round=350)
    train_s = time.time() - t0

    t0 = time.time()
    scores = booster.predict(Xte)
    predict_s = time.time() - t0
    from sklearn.metrics import roc_auc_score

    neg, pos = scores[yte == 0], scores[yte == 1]
    res = {"dataset": "EMBER2024 ELF", "train_shards": ntr_f, "test_shards": nte_f,
           "train_n": int(Xtr.shape[0]), "test_n": int(Xte.shape[0]),
           "test_pos": int(yte.sum()), "test_neg": int((yte == 0).sum()),
           "dims": int(Xtr.shape[1]), "test_weeks": sorted({str(w) for w in wte if w is not None}),
           "load_s": round(load_s, 1), "train_s": round(train_s, 1), "predict_all_s": round(predict_s, 2),
           "auc": round(float(roc_auc_score(yte, scores)), 5), "operating_points": []}
    for fpr_t in (0.0005, 0.001, 0.005, 0.01, 0.02, 0.05):
        thr = float(np.quantile(neg, 1 - fpr_t))
        tp, fp = int((pos >= thr).sum()), int((neg >= thr).sum())
        lo, hi = wilson(tp, len(pos))
        res["operating_points"].append({"target_fpr": fpr_t, "threshold": round(thr, 6),
                                        "tp": tp, "fp": fp, "fpr_measured": round(fp / len(neg), 5),
                                        "tpr": round(tp / len(pos), 5), "tpr_ci95": [round(lo, 4), round(hi, 4)]})

    row = Xte[:1]
    for _ in range(50):
        booster.predict(row)
    lat = []
    for _ in range(300):
        t = time.perf_counter(); booster.predict(row); lat.append((time.perf_counter() - t) * 1000)
    lat.sort()
    res["latency_single_row_ms"] = {"p50": round(lat[150], 3), "p95": round(lat[int(len(lat) * .95)], 3), "max": round(lat[-1], 3)}

    import tempfile, shutil
    tmp_model = os.path.join(tempfile.gettempdir(), "elf_model.txt")
    booster.save_model(tmp_model)
    shutil.copyfile(tmp_model, os.path.join(HERE, "elf_model.txt"))
    with open(OUT, "w") as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps(res, indent=2)[:4000])


if __name__ == "__main__":
    main()

