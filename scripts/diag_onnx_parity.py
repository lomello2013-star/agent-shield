import os
import numpy as np
import lightgbm as lgb
import onnxruntime as ort

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "spikes", "06-ml")


def ascii_copy(src):
    import shutil, tempfile
    fd, dst = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    shutil.copyfile(src, dst)
    return dst


booster = lgb.Booster(model_file=ascii_copy(os.path.join(DATA, "pe_model.txt")))
z = np.load(os.path.join(DATA, "pe_cache.npz"))
X = z["Xte"][:500].astype(np.float32)
p_lgb = booster.predict(X)

sess = ort.InferenceSession(os.path.join(DATA, "pe_model.onnx"), providers=["CPUExecutionProvider"])
out = sess.run(None, {sess.get_inputs()[0].name: X})
print("outputs:", [(np.asarray(o).shape, np.asarray(o).dtype) for o in out])
p_onnx = None
for o in out:
    a = np.asarray(o)
    if a.ndim == 2 and a.shape[1] >= 2:
        p_onnx = a[:, 1]
        break

diff = p_onnx - p_lgb
print("max abs diff", float(np.max(np.abs(diff))))
print("mean diff", float(np.mean(diff)))
print("rows differing >1e-4:", int(np.sum(np.abs(diff) > 1e-4)))

eps = 1e-9
logit = lambda p: np.log(np.clip(p, eps, 1 - eps) / (1 - np.clip(p, eps, 1 - eps)))
d_logit = logit(p_onnx) - logit(p_lgb)
print("logit diff: mean", float(np.mean(d_logit)), "std", float(np.std(d_logit)))
print("first 8:", [round(float(x), 6) for x in d_logit[:8]])
print("p_lgb range", float(p_lgb.min()), float(p_lgb.max()))
