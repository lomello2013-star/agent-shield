"""Export LightGBM file models to ONNX (runtime inference only; no training in runtime).

Produces spikes/06-ml/pe_model.onnx and elf_model.onnx, verifies output parity
against LightGBM predictions on holdout rows, and records sizes.
"""

from __future__ import annotations

import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "spikes", "06-ml")


def _ascii_copy(src: str, suffix: str) -> str:
    """LightGBM's C++ loader cannot open non-ASCII paths: copy to a temp ASCII path."""
    import shutil
    import tempfile
    fd, dst = tempfile.mkstemp(suffix=suffix, prefix="aidf_model_")
    os.close(fd)
    shutil.copyfile(src, dst)
    return dst


def export(name: str, n_features: int, sample_rows: int = 500) -> dict:
    import lightgbm as lgb
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType
    import onnxruntime as ort

    model_path = os.path.join(DATA, f"{name}_model.txt")
    onnx_path = os.path.join(DATA, f"{name}_model.onnx")
    booster = lgb.Booster(model_file=_ascii_copy(model_path, ".txt"))
    t0 = time.perf_counter()
    onnx_model = onnxmltools.convert_lightgbm(
        booster, initial_types=[("input", FloatTensorType([None, n_features]))],
        name=f"aidf-{name}", zipmap=False,
    )
    convert_s = time.perf_counter() - t0
    with open(onnx_path, "wb") as fh:
        fh.write(onnx_model.SerializeToString())
    size_mb = os.path.getsize(onnx_path) / 1e6

    # ONNX Runtime can read the workspace path; only LightGBM's loader needed ASCII.

    # parity on real holdout rows when the cached matrix matches this model
    cache = os.path.join(DATA, "pe_cache.npz")
    X = None
    if os.path.exists(cache):
        z = np.load(cache)
        if z["Xte"].shape[1] == n_features:
            X = z["Xte"][:sample_rows].astype(np.float32)
    if X is None:
        rng = np.random.default_rng(7)
        X = rng.random((sample_rows, n_features), dtype=np.float32)
    expected = booster.predict(X)

    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    input_name = sess.get_inputs()[0].name
    out = sess.run(None, {input_name: X})
    # onnxmltools may emit [label, proba] or a single proba tensor
    proba = None
    for candidate in out:
        arr = np.asarray(candidate)
        if arr.ndim == 2 and arr.shape[0] == len(X) and arr.shape[1] in (2, 3):
            proba = arr[:, 1]
            break
    if proba is None:
        proba = np.asarray(out[0]).reshape(-1)

    diff = np.abs(proba - expected)
    max_diff = float(np.max(diff))
    rows_over = int(np.sum(diff > 1e-4))
    lat = []
    for i in range(200):
        t = time.perf_counter()
        sess.run(None, {input_name: X[i:i + 1]})
        lat.append((time.perf_counter() - t) * 1000)
    lat.sort()
    return {
        "model": name, "features": n_features,
        "convert_s": round(convert_s, 2), "onnx_mb": round(size_mb, 2),
        "rows_checked": len(X), "max_abs_diff": round(max_diff, 6),
        "rows_over_1e-4": rows_over, "rows_over_pct": round(100 * rows_over / len(X), 2),
        "parity_ok": (rows_over / len(X)) < 0.01,
        "latency_ms_p50": round(lat[len(lat) // 2], 3),
        "latency_ms_p95": round(lat[int(len(lat) * 0.95)], 3),
        "providers": sess.get_providers(),
    }


def main() -> None:
    results = [export("pe", 2381)]
    if os.path.exists(os.path.join(DATA, "elf_model.txt")):
        results.append(export("elf", 533))
    print(json.dumps(results, indent=2))
    with open(os.path.join(DATA, "onnx_export.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)


if __name__ == "__main__":
    main()

