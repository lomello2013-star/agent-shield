"""F01: bin-based PPV calibrator.

`confidence` must be the probability that an alert *at that score* is malicious, at the
deployment prevalence. Two candidate mappings were measured on the PE v2 model:

  * tail PPV  — PPV of "score >= threshold": overestimates near the operating point,
    because the tail is dominated by much higher-scoring positives (gap 0.16);
  * bin PPV   — PPV of a narrow score band: matches the deployment-weighted precision
    (gap ≈ 0.01), so this is the one that ships.

The table is fitted offline from labelled scores and stored next to the model.
"""

from __future__ import annotations

import bisect
import json
import os
from dataclasses import dataclass

from core.calibration import CalibrationError
from core.gate import ppv as ppv_formula

METHOD = "bin_ppv"


def _pava(values: list[float], weights: list[float]) -> list[float]:
    """Pool adjacent violators so the table is non-decreasing (isotonic)."""
    blocks = [[v, w, 1] for v, w in zip(values, weights)]
    merged: list[list[float]] = []
    for block in blocks:
        merged.append(block)
        while len(merged) > 1 and merged[-2][0] > merged[-1][0]:
            v2, w2, n2 = merged.pop()
            v1, w1, n1 = merged.pop()
            total = w1 + w2
            mean = (v1 * w1 + v2 * w2) / total if total else (v1 + v2) / 2
            merged.append([mean, total, n1 + n2])
    out: list[float] = []
    for value, _weight, count in merged:
        out.extend([value] * int(count))
    return out


@dataclass
class PPVTableCalibrator:
    """Step function over score bands: confidence = PPV of the band at prevalence."""

    edges: list[float]
    values: list[float]
    prevalence: float
    method: str = METHOD

    def __post_init__(self) -> None:
        if len(self.edges) != len(self.values) + 1:
            raise CalibrationError("edges must be len(values) + 1")
        if any(b <= a for a, b in zip(self.edges, self.edges[1:])):
            raise CalibrationError("edges must be strictly increasing")
        if any(b < a for a, b in zip(self.values, self.values[1:])):
            raise CalibrationError("values must be non-decreasing (monotone PPV)")
        if any(v < 0.0 or v > 1.0 for v in self.values):
            raise CalibrationError("values must be probabilities")
        if not 0.0 < self.prevalence < 1.0:
            raise CalibrationError("prevalence must be within (0, 1)")

    def apply(self, score: float) -> float:
        idx = bisect.bisect_right(self.edges, float(score)) - 1
        idx = min(max(idx, 0), len(self.values) - 1)
        return float(self.values[idx])

    def band(self, score: float) -> tuple[float, float]:
        idx = min(max(bisect.bisect_right(self.edges, float(score)) - 1, 0),
                  len(self.values) - 1)
        return float(self.edges[idx]), float(self.edges[idx + 1])

    def to_json(self) -> dict:
        return {"method": METHOD, "prevalence": self.prevalence,
                "edges": self.edges, "values": self.values}

    @classmethod
    def from_json(cls, payload: dict) -> "PPVTableCalibrator":
        if payload.get("method") != METHOD:
            raise CalibrationError(f"unsupported calibration method: {payload.get('method')}")
        return cls(edges=[float(x) for x in payload["edges"]],
                   values=[float(y) for y in payload["values"]],
                   prevalence=float(payload["prevalence"]))

    @classmethod
    def load(cls, path: str) -> "PPVTableCalibrator":
        if not os.path.exists(path):
            raise CalibrationError(f"calibration file not found: {path}")
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(json.load(fh))


def fit_ppv_table(scores: list[float], labels: list[int], prevalence: float,
                  bins: int = 32) -> PPVTableCalibrator:
    """Fit the band-PPV table on a labelled sample."""
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have equal length")
    if not scores:
        raise ValueError("empty sample")
    pairs = sorted(zip(scores, labels))
    ordered_scores = [float(p[0]) for p in pairs]
    ordered_labels = [int(p[1]) for p in pairs]
    n = len(ordered_scores)
    pos_total = sum(ordered_labels)
    neg_total = n - pos_total
    if pos_total == 0 or neg_total == 0:
        raise ValueError("both classes are required")

    bins = max(2, min(bins, n // 2))
    edges = [ordered_scores[0] - 1e-9]
    for b in range(1, bins):
        edges.append(ordered_scores[min(n - 1, int(n * b / bins))])
    edges.append(ordered_scores[-1] + 1e-9)

    values: list[float] = []
    weights: list[float] = []
    for b in range(bins):
        lo, hi = edges[b], edges[b + 1]
        pos = neg = 0
        for sc, label in zip(ordered_scores, ordered_labels):
            if lo <= sc < hi:
                if label == 1:
                    pos += 1
                else:
                    neg += 1
        tpr = pos / pos_total
        fpr = neg / neg_total
        values.append(ppv_formula(tpr, fpr, prevalence) if (pos or neg) else 0.0)
        weights.append(float(max(1, pos + neg)))

    return PPVTableCalibrator(edges=edges, values=_pava(values, weights),
                              prevalence=prevalence)
