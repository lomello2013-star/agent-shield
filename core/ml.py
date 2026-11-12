"""ONNX inference for file models, in **shadow** mode (stage 8).

Shadow means: the model produces verdicts and metrics, but never triggers an
action. Enforcement is a policy decision that requires FP-budget evidence and a
signed pack; the detector only reports.

No training happens here — `MODELS_TRAIN_ON_DEVICE=False` is immutable and the
runtime only runs pre-trained, signed artifacts.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import numpy as np

from schemas.v3 import Verdict

SEVERITY_BANDS = ((0.99, "critical"), (0.9, "high"), (0.5, "medium"), (0.0, "low"))


def fpr_threshold(benign_scores: list[float], target_fpr: float) -> float:
    """Score threshold that yields at most ``target_fpr`` false positives."""
    if not benign_scores:
        raise ValueError("need benign scores to calibrate")
    if not 0.0 < target_fpr < 1.0:
        raise ValueError("target_fpr must be within (0, 1)")
    return float(np.quantile(np.asarray(benign_scores, dtype=np.float64), 1.0 - target_fpr))


def severity_for(score: float) -> str:
    for bound, severity in SEVERITY_BANDS:
        if score >= bound:
            return severity
    return "low"


@dataclass
class OnnxModel:
    path: str
    input_name: str | None = None
    session: object | None = field(default=None, repr=False)
    load_ms: float = 0.0

    def __post_init__(self) -> None:
        import onnxruntime as ort
        if not os.path.exists(self.path):
            raise FileNotFoundError(self.path)
        t0 = time.perf_counter()
        self.session = ort.InferenceSession(self.path, providers=["CPUExecutionProvider"])
        self.load_ms = round((time.perf_counter() - t0) * 1000, 2)
        if self.input_name is None:
            self.input_name = self.session.get_inputs()[0].name

    @property
    def size_mb(self) -> float:
        return round(os.path.getsize(self.path) / 1e6, 2)

    def predict(self, rows: np.ndarray) -> np.ndarray:
        arr = np.asarray(rows, dtype=np.float32)
        outputs = self.session.run(None, {self.input_name: arr})
        for candidate in outputs:
            out = np.asarray(candidate)
            if out.ndim == 2 and out.shape[0] == arr.shape[0] and out.shape[1] >= 2:
                return out[:, 1].astype(np.float64)
        return np.asarray(outputs[0], dtype=np.float64).reshape(-1)

    def predict_one(self, features: list[float]) -> tuple[float, float]:
        row = np.asarray(features, dtype=np.float32).reshape(1, -1)
        t0 = time.perf_counter()
        score = float(self.predict(row)[0])
        return score, (time.perf_counter() - t0) * 1000.0


@dataclass
class ShadowDetector:
    """Wraps an ONNX model; emits verdicts, never actions."""

    model: OnnxModel
    model_id: str
    model_version: str
    threshold: float = 0.5
    platform: str = "windows"
    calibrator: object | None = None          # IsotonicCalibrator
    train_prevalence: float | None = None      # base rate of the training set
    deploy_prevalence: float | None = None     # expected base rate in the fleet

    alerts: int = 0
    benign_seen: int = 0
    benign_alerts: int = 0
    latencies: list[float] = field(default_factory=list)

    def confidence(self, score: float) -> float:
        """Calibrated confidence, expressed at the deployment base rate.

        Two supported calibrators:
          * `TailPPVCalibrator` — already returns the PPV of the alert tail at the
            deployment prevalence, so no extra adjustment is applied;
          * `IsotonicCalibrator` — fitted per-sample; the prevalence adjustment below
            converts its balanced-set probability to the fleet base rate.
        """
        value = float(score)
        if self.calibrator is not None:
            value = float(self.calibrator.apply(value))
        already_at_deployment = getattr(self.calibrator, "prevalence", None) is not None
        if not already_at_deployment and self.train_prevalence and self.deploy_prevalence:
            from core.calibration import adjust_prevalence
            value = adjust_prevalence(value, self.train_prevalence, self.deploy_prevalence)
        return round(min(max(value, 0.0), 1.0), 6)

    @property
    def confidence_source(self) -> str:
        if self.calibrator is None:
            return "raw_score"
        method = getattr(self.calibrator, "method", None)
        if isinstance(method, str) and method:
            return method                     # "bin_ppv" and future tables
        if getattr(self.calibrator, "prevalence", None) is not None:
            return "prevalence_table"
        return "isotonic_prevalence_adjusted"

    def scan(self, event, features: list[float], ground_truth_malicious: bool | None = None) -> Verdict | None:
        score, latency_ms = self.model.predict_one(features)
        self.latencies.append(latency_ms)
        if score < self.threshold:
            if ground_truth_malicious is False:
                self.benign_seen += 1
            return None
        self.alerts += 1
        if ground_truth_malicious is False:
            self.benign_seen += 1
            self.benign_alerts += 1
        return Verdict(
            verdict_id=__import__("uuid").uuid4(),
            trace_id=event.trace_id,
            event_id=event.event_id,
            detector="file_model",
            model_id=self.model_id,
            model_version=self.model_version,
            platform=event.platform,
            confidence=self.confidence(score),
            severity=severity_for(score),
            reason_code="ml_shadow_score",
            reason_text=(f"shadow file model raw_score={score:.4f} "
                         f"confidence={self.confidence(score):.4f} "
                         f"threshold={self.threshold}"),
        )

    def stats(self) -> dict[str, object]:
        lat = sorted(self.latencies)
        return {
            "alerts": self.alerts,
            "benign_seen": self.benign_seen,
            "benign_alerts": self.benign_alerts,
            "empirical_fpr": (round(self.benign_alerts / self.benign_seen, 6)
                              if self.benign_seen else None),
            "latency_ms_p50": round(lat[len(lat) // 2], 3) if lat else None,
            "latency_ms_p95": round(lat[int(len(lat) * 0.95)], 3) if lat else None,
            "latency_ms_p99": round(lat[int(len(lat) * 0.99)], 3) if lat else None,
            "shadow": True,
        }
