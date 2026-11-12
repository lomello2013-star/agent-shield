import json, glob, os
DATA = os.path.join(os.path.dirname(__file__), "..", "artifacts", "data")
for f in sorted(glob.glob(os.path.join(DATA, "ember2018_*.json"))):
    arr = json.load(open(f))
    ys = [int(r["y"]) for r in arr]
    ls = [int(r["label"]) for r in arr]
    print(os.path.basename(f), "n", len(arr), "y_pos", sum(ys), "label_pos", sum(ls), "equal", ys == ls)
