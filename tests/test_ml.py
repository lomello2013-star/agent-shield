import numpy as np
import pytest

from core.ml import OnnxModel, ShadowDetector, fpr_threshold, severity_for


def test_fpr_threshold_quantile():
    benign = [0.01, 0.02, 0.03, 0.5, 0.9]
    thr = fpr_threshold(benign, 0.2)
    assert 0.02 <= thr <= 0.9
    flagged = sum(1 for s in benign if s >= thr)
    assert flagged <= 1


def test_fpr_threshold_rejects_bad_input():
    with pytest.raises(ValueError):
        fpr_threshold([], 0.1)
    with pytest.raises(ValueError):
        fpr_threshold([0.1], 0.0)


def test_severity_bands():
    assert severity_for(0.995) == "critical"
    assert severity_for(0.95) == "high"
    assert severity_for(0.6) == "medium"
    assert severity_for(0.1) == "low"


class StubModel:
    def __init__(self, score):
        self.score = score

    def predict_one(self, features):
        return self.score, 0.01


def test_shadow_detector_emits_verdict_but_no_action(make_event):
    det = ShadowDetector(model=StubModel(0.97), model_id="pe", model_version="1.0.0",
                         threshold=0.5)
    ev = make_event()
    verdict = det.scan(ev, [0.0] * 4, ground_truth_malicious=True)
    assert verdict is not None
    assert verdict.detector == "file_model"
    assert verdict.model_id == "pe"
    assert verdict.severity == "high"
    assert verdict.confidence == 0.97
    assert verdict.trace_id == ev.trace_id
    stats = det.stats()
    assert stats["alerts"] == 1 and stats["shadow"] is True


def test_shadow_detector_below_threshold_returns_none(make_event):
    det = ShadowDetector(model=StubModel(0.2), model_id="pe", model_version="1.0.0")
    assert det.scan(make_event(), [0.0] * 4, ground_truth_malicious=False) is None
    assert det.stats()["alerts"] == 0
    assert det.stats()["benign_seen"] == 1


def test_shadow_detector_empirical_fpr(make_event):
    det = ShadowDetector(model=StubModel(0.8), model_id="pe", model_version="1.0.0")
    for _ in range(10):
        det.scan(make_event(), [0.0] * 4, ground_truth_malicious=False)
    assert det.stats()["benign_alerts"] == 10
    assert det.stats()["empirical_fpr"] == 1.0


def test_confidence_is_prevalence_adjusted(make_event):
    from core.calibration import IsotonicCalibrator
    identity = IsotonicCalibrator(thresholds=[0.0, 1.0], values=[0.0, 1.0])
    det = ShadowDetector(model=StubModel(0.99), model_id="pe", model_version="1.0.0",
                         threshold=0.5, calibrator=identity,
                         train_prevalence=0.5, deploy_prevalence=0.001)
    verdict = det.scan(make_event(), [0.0] * 4, ground_truth_malicious=True)
    assert verdict is not None
    assert 0.08 < verdict.confidence < 0.10      # LR-preserving adjustment
    assert "raw_score=0.9900" in verdict.reason_text


def test_confidence_without_calibration_is_raw_score(make_event):
    det = ShadowDetector(model=StubModel(0.77), model_id="pe", model_version="1.0.0")
    verdict = det.scan(make_event(), [0.0] * 4)
    assert verdict is not None and verdict.confidence == 0.77


def test_onnx_model_predicts_and_matches_lightgbm(tmp_path):
    import lightgbm as lgb
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType

    rng = np.random.default_rng(11)
    X = rng.random((400, 4)).astype(np.float32)
    y = (X[:, 0] + X[:, 1] > 1.0).astype(int)
    booster = lgb.train({"objective": "binary", "verbose": -1, "num_leaves": 8,
                         "min_data_in_leaf": 5}, lgb.Dataset(X, label=y), num_boost_round=15)
    onnx_model = onnxmltools.convert_lightgbm(
        booster, initial_types=[("input", FloatTensorType([None, 4]))], zipmap=False)
    path = tmp_path / "toy.onnx"
    path.write_bytes(onnx_model.SerializeToString())

    model = OnnxModel(str(path))
    assert model.load_ms >= 0 and model.size_mb > 0
    sample = X[:50]
    got = model.predict(sample)
    expected = booster.predict(sample)
    assert np.max(np.abs(got - expected)) < 1e-3

    score, latency = model.predict_one([0.9, 0.9, 0.0, 0.0])
    assert 0.0 <= score <= 1.0 and latency >= 0


def test_onnx_model_missing_file():
    with pytest.raises(FileNotFoundError):
        OnnxModel("does-not-exist.onnx")


def test_confidence_from_ppv_table_is_not_adjusted_twice(make_event):
    """F01: a band-PPV calibrator already expresses deployment probability."""
    from core.ppv_calibration import PPVTableCalibrator
    table = PPVTableCalibrator(edges=[0.0, 0.5, 1.0], values=[0.01, 0.4],
                               prevalence=0.001)
    det = ShadowDetector(model=StubModel(0.9), model_id="pe", model_version="1.0.0",
                         threshold=0.5, calibrator=table,
                         train_prevalence=0.5, deploy_prevalence=0.001)
    verdict = det.scan(make_event(), [0.0] * 4)
    assert verdict is not None
    assert verdict.confidence == 0.4          # table value, no second adjustment
    assert det.confidence_source == "bin_ppv"
