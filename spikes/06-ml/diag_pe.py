import json, glob, os
import numpy as np

DATA = os.path.join(os.path.dirname(__file__), "..", "artifacts", "data")
f = sorted(glob.glob(os.path.join(DATA, "ember2018_train_1.json")))[0]
arr = json.load(open(f))
print("n_train1", len(arr), "keys", list(arr[0].keys()), "dim", len(arr[0]["x"]))
print("y_counts", {k: sum(1 for r in arr if int(r["y"]) == k) for k in (0, 1)})
x = np.asarray([r["x"] for r in arr[:200]], dtype=np.float32)
print("x stats: min", float(x.min()), "max", float(x.max()), "mean", float(x.mean()), "nonzero_frac", float((x != 0).mean()))

res = json.load(open(os.path.join(os.path.dirname(__file__), "ml_pe_result.json")))
print("auc", res["auc"], "dims", res["dims"], "train_n", res["train_n"], "test_n", res["test_n"])
print("first 3 ops:", res["operating_points"][:3])
