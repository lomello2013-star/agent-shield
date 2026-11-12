"""Runtime score calibration (isotonic, offline-fitted).

The contract (`data-model-v3.md` §4) requires `Verdict.confidence` to be a
*calibrated* probability. Fitting happens offline; the runtime only applies a
piecewise-linear mapping shipped with the model (as signed pack metadata).
"""

from __future__ import annotations

import bisect
import json
import os
from dataclasses import dataclass


class CalibrationError(ValueError):
    """Invalid calibration table (non-monotonic, empty, out of range)."""


@dataclass
class IsotonicCalibrator:
    """Piecewise-linear interpolation over monotonic knots."""

    thresholds: list[float]
    values: list[float]

    def __post_init__(self) -> None:
        if not self.thresholds or len(self.thresholds) != len(self.values):
            raise CalibrationError("thresholds and values must be non-empty and equal length")
        if any(b <= a for a, b in zip(self.thresholds, self.thresholds[1:])):
            raise CalibrationError("thresholds must be strictly increasing")
        if any(b < a for a, b in zip(self.values, self.values[1:])):
            raise CalibrationError("values must be non-decreasing (isotonic)")
        if any(v < 0.0 or v > 1.0 for v in self.values):
            raise CalibrationError("values must be probabilities")

    def apply(self, score: float) -> float:
        x = float(score)
        if x <= self.thresholds[0]:
            return float(self.values[0])
        if x >= self.thresholds[-1]:
            return float(self.values[-1])
        idx = bisect.bisect_right(self.thresholds, x) - 1
        x0, x1 = self.thresholds[idx], self.thresholds[idx + 1]
        y0, y1 = self.values[idx], self.values[idx + 1]
        if x1 == x0:
            return float(y1)
        return float(y0 + (y1 - y0) * (x - x0) / (x1 - x0))

    def to_json(self) -> dict:
        return {"method": "isotonic", "thresholds": self.thresholds, "values": self.values}

    @classmethod
    def from_json(cls, payload: dict) -> "IsotonicCalibrator":
        if payload.get("method") != "isotonic":
            raise CalibrationError(f"unsupported calibration method: {payload.get('method')}")
        return cls(thresholds=[float(x) for x in payload["thresholds"]],
                   values=[float(y) for y in payload["values"]])

    @classmethod
    def load(cls, path: str) -> "IsotonicCalibrator":
        if not os.path.exists(path):
            raise CalibrationError(f"calibration file not found: {path}")
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(json.load(fh))


def adjust_prevalence(probability: float, train_prevalence: float,
                      deploy_prevalence: float) -> float:
    """Re-map a probability from the training base rate to the deployment base rate.

    A model trained on a ~50/50 dataset outputs P(malicious | features) *for that
    base rate*. At a deployment prevalence of 1/1000 the same evidence means a much
    lower probability. Ignoring this is how "0.99 confidence" ends up next to a
    precision of 8 % — the confidence must describe deployment, not the dataset.
    """
    if not 0.0 < train_prevalence < 1.0 or not 0.0 < deploy_prevalence < 1.0:
        raise ValueError("prevalences must be within (0, 1)")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be within 0..1")
    if train_prevalence == deploy_prevalence:
        return float(probability)
    odds = (deploy_prevalence / (1.0 - deploy_prevalence)) / (
        train_prevalence / (1.0 - train_prevalence))
    p = min(max(float(probability), 1e-12), 1.0 - 1e-12)
    adjusted = (p * odds) / (p * odds + (1.0 - p))
    return float(min(max(adjusted, 0.0), 1.0))


def ece(probs: list[float], labels: list[int], bins: int = 10) -> float:
    """Expected calibration error (uniform bins)."""
    if len(probs) != len(labels):
        raise ValueError("probs and labels must have equal length")
    if not probs:
        return 0.0
    total = len(probs)
    err = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, p in enumerate(probs) if (p >= lo and p < hi) or (b == bins - 1 and p == 1.0)]
        if not idx:
            continue
        avg_conf = sum(probs[i] for i in idx) / len(idx)
        avg_true = sum(labels[i] for i in idx) / len(idx)
        err += abs(avg_conf - avg_true) * len(idx) / total
    return err


def brier(probs: list[float], labels: list[int]) -> float:
    if len(probs) != len(labels):
        raise ValueError("probs and labels must have equal length")
    if not probs:
        return 0.0
    return sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(probs)
