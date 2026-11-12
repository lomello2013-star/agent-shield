import json
import os

import pytest

from core.safemode import ConfigError, SafeMode, config_fingerprint, validate_config

GOOD = {
    "schema_version": "1.0",
    "sources": ["win.etw.ti", "win.amsi"],
    "thresholds": {"alert_per_host_per_14d": 1, "fpr": 0.001},
    "queue": {"capacity": 10000},
    "allowlist": [],
}


def test_valid_config_passes():
    validate_config(GOOD)
    validate_config({**GOOD, "schema_version": "1.1"})


@pytest.mark.parametrize("cfg", [
    {"schema_version": "1.0", "sources": ["a"]},                          # missing thresholds
    {**GOOD, "unknown_key": 1},                                          # unknown key
    {**GOOD, "sources": "not-a-list"},                                   # wrong type
    {**GOOD, "sources": [""]},                                           # empty source
    {**GOOD, "thresholds": {"x": -1}},                                   # negative threshold
    {**GOOD, "thresholds": {"x": "high"}},                               # non-numeric
    "not-an-object",
])
def test_invalid_configs_rejected(cfg):
    with pytest.raises(ConfigError):
        validate_config(cfg)


def test_fingerprint_is_deterministic_and_order_insensitive():
    a = config_fingerprint(GOOD)
    b = config_fingerprint(dict(reversed(list(GOOD.items()))))
    assert a == b and len(a) == 64


def test_save_and_load_lkg(tmp_path):
    sm = SafeMode(tmp_path)
    fp = sm.save_lkg(GOOD)
    assert fp == config_fingerprint(GOOD)
    assert sm.load_lkg() == GOOD


def test_lkg_checksum_tamper_detected(tmp_path):
    sm = SafeMode(tmp_path)
    sm.save_lkg(GOOD)
    path = os.path.join(sm.lkg_dir, "config.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({**GOOD, "thresholds": {"alert_per_host_per_14d": 999}}, fh)
    with pytest.raises(ConfigError):
        sm.load_lkg()


def test_load_lkg_missing_returns_none(tmp_path):
    assert SafeMode(tmp_path).load_lkg() is None


def test_apply_invalid_enters_safe_mode_without_persisting(tmp_path):
    sm = SafeMode(tmp_path)
    res = sm.apply({**GOOD, "bogus": 1}, dry_run=False)
    assert res.accepted is False
    assert sm.is_safe is True
    assert "unknown config keys" in sm.reason
    assert sm.load_lkg() is None


def test_apply_dry_run_does_not_write(tmp_path):
    sm = SafeMode(tmp_path)
    res = sm.apply(GOOD, dry_run=True)
    assert res.accepted and res.dry_run
    assert sm.load_lkg() is None


def test_apply_real_writes_lkg(tmp_path):
    sm = SafeMode(tmp_path)
    res = sm.apply(GOOD, dry_run=False)
    assert res.accepted and res.mode == "normal"
    assert sm.load_lkg() == GOOD


def test_safe_mode_exit_requires_operator(tmp_path):
    sm = SafeMode(tmp_path)
    sm.enter("bad model pack")
    assert sm.status()["safe_mode"] is True
    assert sm.exit(operator=False) is False
    assert sm.is_safe is True
    assert sm.exit(operator=True) is True
    assert sm.is_safe is False and sm.reason == ""
