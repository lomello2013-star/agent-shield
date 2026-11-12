import pytest

from core.updater import DualSlot, UpdateError, canary_selected


def make_slot(tmp_path):
    return DualSlot(str(tmp_path))


def test_initial_pointer_is_slot_a(tmp_path):
    ds = make_slot(tmp_path)
    assert ds.active_slot() == "A"
    assert ds.inactive_slot() == "B"


def test_stage_verify_activate(tmp_path):
    ds = make_slot(tmp_path)
    staged = ds.stage("1.1.0", {"bin/aidfd": b"v1", "rules/r.json": b"{}"})
    assert staged["slot"] == "B"
    assert ds.verify_slot("B")
    pointer = ds.activate("B", "1.1.0")
    assert pointer["slot"] == "B" and pointer["previous"] == "A"
    assert ds.active_slot() == "B"


def test_activate_unverified_slot_refused(tmp_path):
    ds = make_slot(tmp_path)
    with pytest.raises(UpdateError):
        ds.activate("B", "1.1.0")


def test_rollback_restores_previous_slot(tmp_path):
    ds = make_slot(tmp_path)
    ds.stage("1.1.0", {"f": b"new"})
    ds.activate("B", "1.1.0")
    pointer = ds.rollback()
    assert pointer["slot"] == "A"
    assert ds.active_slot() == "A"


def test_rollback_without_previous_raises(tmp_path):
    ds = make_slot(tmp_path)
    with pytest.raises(UpdateError):
        ds.rollback()


def test_update_with_health_gate_success(tmp_path):
    ds = make_slot(tmp_path)
    res = ds.update_with_health_gate("1.2.0", {"f": b"x"}, health=lambda: True)
    assert res["result"] == "updated"
    assert ds.active_slot() == "B"


def test_update_with_health_gate_rolls_back_on_regression(tmp_path):
    ds = make_slot(tmp_path)
    res = ds.update_with_health_gate("1.2.0", {"f": b"x"}, health=lambda: False)
    assert res["result"] == "rolled_back" and res["regression"] is True
    assert ds.active_slot() == "A"


def test_health_gate_treats_exception_as_failure(tmp_path):
    ds = make_slot(tmp_path)
    def boom():
        raise RuntimeError("health probe crashed")
    res = ds.update_with_health_gate("1.3.0", {"f": b"y"}, health=boom)
    assert res["result"] == "rolled_back"
    assert ds.active_slot() == "A"


def test_unsafe_payload_path_rejected(tmp_path):
    ds = make_slot(tmp_path)
    with pytest.raises(UpdateError):
        ds.stage("1.4.0", {"../escape.txt": b"bad"})


def test_canary_is_deterministic():
    assert canary_selected("host-1", "rel-42", 1.0) == canary_selected("host-1", "rel-42", 1.0)


def test_canary_ratio_near_percent():
    hosts = [f"host-{i}" for i in range(4000)]
    selected = sum(canary_selected(h, "release-2026-11", 1.0) for h in hosts)
    assert 10 <= selected <= 70, selected          # ~1% of 4000, generous bounds
    assert canary_selected("host", "rel", 100.0)
    assert not canary_selected("host", "rel", 0.0)


def test_kill_switch_roundtrip(tmp_path):
    ds = make_slot(tmp_path)
    assert ds.is_killed("rule-7") is False
    ds.set_kill_switch("rule-7", True)
    assert ds.is_killed("rule-7") is True
    ds.set_kill_switch("rule-7", False)
    assert ds.is_killed("rule-7") is False


def test_corrupt_slot_fails_verification(tmp_path):
    ds = make_slot(tmp_path)
    ds.stage("1.5.0", {"f": b"content"})
    with open(tmp_path / "slots" / "B" / "f", "wb") as fh:
        fh.write(b"tampered")
    assert ds.verify_slot("B") is False
