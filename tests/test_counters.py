import pytest

from core.counters import BACKLOG, LOST, OVERFLOW, LossCounters


def test_counters_increment_and_snapshot():
    c = LossCounters()
    c.inc(LOST)
    c.inc(LOST, 2)
    c.inc(BACKLOG, 5)
    assert c.get(LOST) == 3
    assert c.snapshot()[BACKLOG] == 5


def test_loss_callback_fires_for_lost_and_overflow_only():
    seen = []
    c = LossCounters(on_loss=lambda name, n: seen.append((name, n)))
    c.inc(BACKLOG, 10)
    c.inc(LOST, 2)
    c.inc(OVERFLOW, 1)
    assert seen == [(LOST, 2), (OVERFLOW, 1)]


def test_negative_delta_rejected():
    c = LossCounters()
    with pytest.raises(ValueError):
        c.inc(LOST, -1)


def test_clean_state():
    c = LossCounters()
    assert c.is_clean()
    c.inc(OVERFLOW)
    assert not c.is_clean()
    assert c.loss_total() == 1


def test_set_updates_gauge():
    c = LossCounters()
    c.set(BACKLOG, 42)
    assert c.get(BACKLOG) == 42
