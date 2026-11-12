"""Export the 50k PE holdout for the Rust ort test.

Writes rust/target/pe_holdout_50k/{rows.f32,scores.f32,meta.json}.
Run from the repository root:

    python rust/export_holdout.py
"""

from __future__ import annotations

import json
import pathlib

import numpy as np
import onnxruntime as ort

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / "spikes" / "06-ml" / "pe_cache.npz"
MODEL = ROOT / "spikes" / "06-ml" / "pe_model.onnx"
OUT = ROOT / "rust" / "target" / "pe_holdout_50k"


def main() -> None:
    cache = np.load(CACHE)
    rows = cache["Xte"].astype(np.float32)
    OUT.mkdir(parents=True, exist_ok=True)
    rows.tofile(OUT / "rows.f32")

    session = ort.InferenceSession(str(MODEL), providers=["CPUExecutionProvider"])
    scores = session.run(None, {"input": rows})[1][:, 1].astype(np.float32)
    scores.tofile(OUT / "scores.f32")
    (OUT / "meta.json").write_text(
        json.dumps(
            {
                "rows": int(rows.shape[0]),
                "features": int(rows.shape[1]),
                "scores": f"onnxruntime {ort.__version__}",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"wrote {rows.shape[0]} rows x {rows.shape[1]} features to {OUT}")


if __name__ == "__main__":
    main()
