import pytest

from core.calibration import (
    CalibrationError,
    IsotonicCalibrator,
    adjust_prevalence,
    brier,
    ece,
)

KNOTS = {"method": "isotonic",
         "thresholds": [0.0, 0.5, 0.9, 1.0],
         "values": [0.0, 0.2, 0.8, 1.0]}


def test_calibrator_interpolates_and_clamps():
    cal = IsotonicCalibrator.from_json(KNOTS)
    assert cal.apply(-1.0) == 0.0
    assert cal.apply(0.0) == 0.0
    assert cal.apply(0.25) == pytest.approx(0.1)
    assert cal.apply(0.7) == pytest.approx(0.5)
    assert cal.apply(1.0) == 1.0
    assert cal.apply(2.0) == 1.0


def test_calibrator_roundtrip_json(tmp_path):
    cal = IsotonicCalibrator.from_json(KNOTS)
    path = tmp_path / "cal.json"
    import json
    path.write_text(json.dumps(cal.to_json()), encoding="utf-8")
    again = IsotonicCalibrator.load(str(path))
    assert again.thresholds == cal.thresholds and again.values == cal.values


@pytest.mark.parametrize("bad", [
    {"method": "isotonic", "thresholds": [], "values": []},
    {"method": "isotonic", "thresholds": [0.0, 0.5], "values": [0.5]},
    {"method": "isotonic", "thresholds": [0.0, 0.0], "values": [0.0, 0.5]},
    {"method": "isotonic", "thresholds": [0.0, 0.5], "values": [0.6, 0.2]},
    {"method": "isotonic", "thresholds": [0.0, 0.5], "values": [0.0, 1.5]},
    {"method": "platt", "thresholds": [0.0], "values": [0.0]},
])
def test_calibrator_rejects_invalid_tables(bad):
    with pytest.raises(CalibrationError):
        IsotonicCalibrator.from_json(bad)


def test_calibrator_load_missing_file():
    with pytest.raises(CalibrationError):
        IsotonicCalibrator.load("no-such-file.json")


def test_prevalence_adjustment_matches_likelihood_ratio():
    # 0.99 on a balanced set means LR ~ 99; at 1/1000 prior that is ~9 % posterior
    adjusted = adjust_prevalence(0.99, 0.5, 0.001)
    assert 0.08 < adjusted < 0.10
    assert adjust_prevalence(0.5, 0.5, 0.001) == pytest.approx(0.001)


def test_prevalence_adjustment_identity_and_validation():
    assert adjust_prevalence(0.37, 0.2, 0.2) == pytest.approx(0.37)
    with pytest.raises(ValueError):
        adjust_prevalence(1.2, 0.5, 0.001)
    with pytest.raises(ValueError):
        adjust_prevalence(0.5, 0.0, 0.001)


def test_ece_and_brier():
    assert brier([0.0, 1.0], [0, 1]) == 0.0
    assert brier([0.5, 0.5], [1, 0]) == pytest.approx(0.25)
    # perfectly calibrated bins: confidence 0.5, half positives
    assert ece([0.5, 0.5], [1, 0]) == pytest.approx(0.0)
    # overconfident predictions
    assert ece([0.9, 0.9], [0, 0]) == pytest.approx(0.9)
    with pytest.raises(ValueError):
        brier([0.5], [0, 1])


# ---------------------------------------------------------------- F01: band PPV
from core.ppv_calibration import PPVTableCalibrator, fit_ppv_table  # noqa: E402


def test_fit_ppv_table_is_monotone_and_typed():
    scores = [round(i / 1000, 3) for i in range(1000)]
    labels = [1 if s > 0.8 else (1 if s > 0.6 and s < 0.61 else 0) for s in scores]
    table = fit_ppv_table(scores, labels, prevalence=0.001, bins=16)
    assert len(table.edges) == len(table.values) + 1
    assert all(b >= a for a, b in zip(table.values, table.values[1:]))
    assert all(0.0 <= v <= 1.0 for v in table.values)
    # higher score must never map to lower confidence
    assert table.apply(0.9) >= table.apply(0.5)


def test_ppv_table_bands():
    table = PPVTableCalibrator(edges=[0.0, 0.5, 0.9, 1.0], values=[0.0, 0.2, 0.9],
                               prevalence=0.001)
    assert table.apply(0.1) == 0.0
    assert table.apply(0.7) == 0.2
    assert table.apply(0.95) == 0.9
    lo, hi = table.band(0.95)
    assert lo == 0.9 and hi == 1.0


@pytest.mark.parametrize("bad", [
    {"prevalence": 0.001, "edges": [0.0, 0.5], "values": [0.0, 0.1]},   # 2 values, 2 edges                      # wrong length
    {"prevalence": 0.001, "edges": [0.5, 0.5, 1.0], "values": [0.0, 0.5]},            # non-increasing edges
    {"prevalence": 0.001, "edges": [0.0, 0.5, 1.0], "values": [0.6, 0.2]},            # non-monotone values
    {"prevalence": 0.001, "edges": [0.0, 1.0], "values": [0.0, 1.5]},                 # probability range
    {"edges": [0.0, 1.0], "values": [0.0, 0.5], "prevalence": 0},   # bad prevalence
])
def test_ppv_table_rejects_invalid(bad):
    with pytest.raises(CalibrationError):
        PPVTableCalibrator(**bad)


def test_ppv_table_roundtrip_json(tmp_path):
    table = PPVTableCalibrator(edges=[0.0, 0.5, 1.0], values=[0.0, 0.4],
                               prevalence=0.001)
    import json as _json
    path = tmp_path / "ppv.json"
    path.write_text(_json.dumps(table.to_json()), encoding="utf-8")
    again = PPVTableCalibrator.load(str(path))
    assert again.values == table.values and again.prevalence == table.prevalence


def test_ppv_table_rejects_wrong_method():
    with pytest.raises(CalibrationError):
        PPVTableCalibrator.from_json({"method": "isotonic", "prevalence": 0.001,
                                      "edges": [0.0, 1.0], "values": [0.0]})


