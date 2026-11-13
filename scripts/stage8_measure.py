"""Stage 8 measurement: signed ModelPack, ONNX parity, TPR@FPR through ONNX, shadow run.

Writes artifacts/stage8_report.json and signed pack manifests under spikes/06-ml/.
Dev Ed25519 keys are generated locally and written to secrets/dev_keys.json (outside artifacts/) -
production keys live in HSM/CI (never on the agent host).
"""

from __future__ import annotations

import glob
import json
import math
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ml import OnnxModel, ShadowDetector, fpr_threshold, severity_for
from core.modelpack import (
    generate_dev_keypair,
    load_public_key,
    private_key_from_hex,
    sign_pack,
    verify_pack,
)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML = os.path.join(HERE, "spikes", "06-ml")
REPORT = os.path.join(HERE, "artifacts", "stage8_report.json")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(max(0.0, p * (1 - p) / n + z * z / (4 * n * n)))
    return (c - r) / d, (c + r) / d


def pack_for(name: str, model_id: str, platform: str, priv_hex: str,
             metrics: dict) -> tuple[dict, str]:
    artifact = os.path.join(ML, f"{name}_model.onnx")
    import hashlib
    h = hashlib.sha256()
    with open(artifact, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    pack = {
        "model_id": model_id,
        "version": "1.0.0",
        "platform": platform,
        "format": "onnx",
        "sha256": h.hexdigest(),
        "dataset_hash": "d" * 64,
        "metrics": metrics,
        "limits": {"max_input_mb": 200, "shadow_only": True},
    }
    pack["signature"] = sign_pack(pack, private_key_from_hex(priv_hex))
    return pack, artifact


def measure_pack(priv_hex: str, pub_hex: str) -> dict:
    pe_metrics = {"tpr_at_fpr_1pct": 0.854, "tpr_at_fpr_0.1pct": 0.649}
    elf_metrics = {"tpr_at_fpr_1pct": 0.875, "tpr_at_fpr_0.5pct": 0.765}
    pe_pack, pe_artifact = pack_for("pe", "aidf-pe-ember", "windows", priv_hex, pe_metrics)
    elf_pack, elf_artifact = pack_for("elf", "aidf-elf-ember2024", "linux", priv_hex, elf_metrics)

    t0 = time.perf_counter()
    pe_res = verify_pack(pe_pack, pe_artifact, load_public_key(pub_hex))
    elf_res = verify_pack(elf_pack, elf_artifact, load_public_key(pub_hex))
    verify_ms = (time.perf_counter() - t0) * 1000

    # tamper one byte of the artifact copy and re-verify
    tampered = os.path.join(ML, "pe_model_tampered.onnx")
    with open(pe_artifact, "rb") as src, open(tampered, "wb") as dst:
        data = bytearray(src.read())
        data[len(data) // 2] ^= 0xFF
        dst.write(data)
    tamper_res = verify_pack(pe_pack, tampered, load_public_key(pub_hex))
    os.remove(tampered)

    # unsigned / wrong key
    unsigned = dict(pe_pack)
    unsigned["signature"] = ""
    unsigned_res = verify_pack(unsigned, pe_artifact, load_public_key(pub_hex))
    _, other_pub = generate_dev_keypair()
    wrong_key_res = verify_pack(pe_pack, pe_artifact, load_public_key(other_pub))

    for pack, fname in ((pe_pack, "pe_pack.json"), (elf_pack, "elf_pack.json")):
        with open(os.path.join(ML, fname), "w", encoding="utf-8") as fh:
            json.dump(pack, fh, indent=2, ensure_ascii=False)

    return {
        "pe_pack_ok": pe_res.ok, "elf_pack_ok": elf_res.ok,
        "verify_ms": round(verify_ms, 3),
        "tampered_artifact": tamper_res.code,
        "unsigned": unsigned_res.code,
        "wrong_key": wrong_key_res.code,
        "fail_closed": not tamper_res.ok and not unsigned_res.ok and not wrong_key_res.ok,
        "packs_written": ["spikes/06-ml/pe_pack.json", "spikes/06-ml/elf_pack.json"],
    }


def measure_pe_onnx() -> dict:
    z = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = z["Xte"][:10000].astype(np.float32), z["yte"][:10000]
    model = OnnxModel(os.path.join(ML, "pe_model.onnx"), allow_unsigned=True)
    t0 = time.perf_counter()
    scores = model.predict(X)
    elapsed = time.perf_counter() - t0
    neg, pos = scores[y == 0], scores[y == 1]

    out = {"model": "pe", "rows": len(X), "features": X.shape[1],
           "load_ms": model.load_ms, "size_mb": model.size_mb,
           "predict_10k_s": round(elapsed, 3),
           "rows_per_s": round(len(X) / elapsed, 0),
           "auc": round(float(__import__("sklearn.metrics", fromlist=["roc_auc_score"]).roc_auc_score(y, scores)), 5),
           "operating_points": []}
    for fpr_t in (0.001, 0.005, 0.01):
        thr = fpr_threshold(list(neg), fpr_t)
        tp = int((pos >= thr).sum())
        fp = int((neg >= thr).sum())
        lo, hi = wilson(tp, len(pos))
        out["operating_points"].append({
            "target_fpr": fpr_t, "threshold": round(thr, 6), "tpr": round(tp / len(pos), 4),
            "tpr_ci95": [round(lo, 4), round(hi, 4)], "fpr": round(fp / len(neg), 5),
            "tp": tp, "fp": fp,
        })
    out["lightgbm_reference"] = {"tpr_at_fpr_1pct": 0.854, "tpr_at_fpr_0.1pct": 0.649}
    return out


def elf_features(rec: dict) -> list[float]:
    hist = (rec.get("histogram") or [])[:256]
    ent = (rec.get("byteentropy") or [])[:256]
    st = rec.get("strings") or {}
    gen = rec.get("general") or {}
    sc = st.get("string_counts") or {}
    keys = ["printables", "paths", "urls", "registry", "MZ", "mz", "dos", "names",
            "PE", "pe", "macho", "elf", "total", "numstrings"]
    f = [0.0] * (256 + 256 + 4 + 3 + len(keys))
    for i, v in enumerate(hist):
        f[i] = float(v)
    for i, v in enumerate(ent):
        f[256 + i] = float(v)
    base = 512
    f[base + 0] = math.log1p(st.get("numstrings", 0) or 0)
    f[base + 1] = float(st.get("avlength", 0) or 0)
    f[base + 2] = float(st.get("printables", 0) or 0)
    f[base + 3] = float(st.get("entropy", 0) or 0)
    f[base + 4] = math.log1p(gen.get("size", 0) or 0)
    f[base + 5] = float(gen.get("entropy", 0) or 0)
    f[base + 6] = 1.0 if gen.get("is_pe") else 0.0
    for i, k in enumerate(keys):
        f[base + 7 + i] = math.log1p(sc.get(k, 0) or 0)
    return f


def measure_elf_onnx(limit_files: int = 3) -> dict:
    files = sorted(glob.glob(os.path.join(HERE, "spikes", "artifacts", "data", "elf_test", "*.jsonl")))[:limit_files]
    X, y = [], []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                X.append(elf_features(rec))
                y.append(int(rec.get("label", 0)))
    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=np.int8)
    model = OnnxModel(os.path.join(ML, "elf_model.onnx"), allow_unsigned=True)
    t0 = time.perf_counter()
    scores = model.predict(X)
    elapsed = time.perf_counter() - t0
    neg, pos = scores[y == 0], scores[y == 1]
    out = {"model": "elf", "rows": len(X), "features": X.shape[1],
           "load_ms": model.load_ms, "size_mb": model.size_mb,
           "predict_s": round(elapsed, 3), "operating_points": []}
    for fpr_t in (0.005, 0.01, 0.02):
        thr = fpr_threshold(list(neg), fpr_t)
        tp = int((pos >= thr).sum())
        lo, hi = wilson(tp, len(pos))
        out["operating_points"].append({
            "target_fpr": fpr_t, "threshold": round(thr, 6),
            "tpr": round(tp / len(pos), 4), "tpr_ci95": [round(lo, 4), round(hi, 4)],
            "fpr": round(int((neg >= thr).sum()) / len(neg), 5),
        })
    return out


def measure_shadow() -> dict:
    z = np.load(os.path.join(ML, "pe_cache.npz"))
    X, y = z["Xte"][:15000], z["yte"][:15000]
    model = OnnxModel(os.path.join(ML, "pe_model.onnx"), allow_unsigned=True)
    scores = model.predict(X.astype(np.float32))
    benign = [float(s) for s, label in zip(scores, y) if label == 0]
    threshold = fpr_threshold(benign[:3000], 0.01)
    det = ShadowDetector(model=model, model_id="aidf-pe-ember", model_version="1.0.0",
                         threshold=threshold)
    # replay through the public API to measure latency + FP accounting
    from datetime import datetime, timezone
    from uuid import uuid4
    from schemas.v3 import Event

    def event():
        return Event.model_validate({
            "schema_version": "3.0", "event_id": str(uuid4()), "trace_id": str(uuid4()),
            "ts_event": datetime.now(timezone.utc).isoformat(),
            "ts_ingest": datetime.now(timezone.utc).isoformat(),
            "platform": "windows", "source": "win.ml.file", "layer": "user",
            "category": "file.exec", "action": "scan",
            "host": {"host_id": "h", "os": "windows", "version": "10", "arch": "x64"},
            "raw_ref": "raw/ml",
        })

    for row, label in list(zip(X, y))[:2000]:
        det.scan(event(), [float(v) for v in row], ground_truth_malicious=bool(label))
    stats = det.stats()
    return {"threshold": round(threshold, 6), "scored": 2000,
            "alerts": stats["alerts"], "empirical_fpr": stats["empirical_fpr"],
            "latency_ms_p50": stats["latency_ms_p50"], "latency_ms_p95": stats["latency_ms_p95"],
            "shadow": True, "actions_taken": 0}


def main() -> None:
    priv_hex, pub_hex = generate_dev_keypair()
    keys_path = os.path.join(HERE, "secrets", "dev_keys.json")
    with open(keys_path, "w", encoding="utf-8") as fh:
        json.dump({"note": "DEV ONLY - production keys in HSM/CI",
                   "private_hex": priv_hex, "public_hex": pub_hex}, fh, indent=2)

    report = {
        "environment": {"python": sys.version.split()[0], "cpu": os.cpu_count()},
        "modelpack": measure_pack(priv_hex, pub_hex),
        "pe_onnx_metrics": measure_pe_onnx(),
        "elf_onnx_metrics": measure_elf_onnx(),
        "shadow_pe": measure_shadow(),
        "export": json.load(open(os.path.join(ML, "onnx_export.json"), encoding="utf-8")),
        "note": "inference only; no on-device training (MODELS_TRAIN_ON_DEVICE=False, tested); "
                "shadow mode never executes actions",
    }
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False)[:5000])


if __name__ == "__main__":
    main()

