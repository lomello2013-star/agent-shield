import pytest

from core.confirm import ConfirmationManager


class FakeClock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def test_timeout_rejects_per_immutable_policy():
    clock = FakeClock()
    mgr = ConfirmationManager(default_timeout_s=30, now_fn=clock)
    conf = mgr.request("act-1", level="protected_dir")
    assert conf.decision == "pending"
    clock.t += 31
    expired = mgr.expire()
    assert expired and expired[0].decision == "reject"      # FAIL_SAFE_ON_TIMEOUT
    assert mgr.executable(conf.confirmation_id) is False


def test_below_timeout_stays_pending():
    clock = FakeClock()
    mgr = ConfirmationManager(default_timeout_s=30, now_fn=clock)
    conf = mgr.request("act-2")
    clock.t += 10
    assert mgr.expire() == []
    assert conf.decision == "pending"


def test_destructive_without_operator_is_queued_never_executed():
    mgr = ConfirmationManager(operator_present=False)
    conf = mgr.request("terminate", destructive=True)
    assert conf.queued is True
    mgr.resolve(conf.confirmation_id, "approved")
    assert conf.decision == "pending"          # still not approved
    assert mgr.executable(conf.confirmation_id) is False
    assert mgr.pending() == [conf]


def test_destructive_with_operator_can_be_approved():
    mgr = ConfirmationManager(operator_present=True)
    conf = mgr.request("terminate", destructive=True)
    mgr.resolve(conf.confirmation_id, "approved")
    assert conf.decision == "approved"
    assert mgr.executable(conf.confirmation_id) is True


def test_reversible_action_approval_and_execution_gate():
    mgr = ConfirmationManager()
    conf = mgr.request("suspend")
    assert mgr.executable(conf.confirmation_id) is False
    mgr.resolve(conf.confirmation_id, "approved")
    assert mgr.executable(conf.confirmation_id) is True


def test_double_resolution_is_idempotent():
    mgr = ConfirmationManager()
    conf = mgr.request("block_network")
    mgr.resolve(conf.confirmation_id, "rejected")
    mgr.resolve(conf.confirmation_id, "approved")     # second call ignored
    assert conf.decision == "rejected"


def test_bad_decision_and_level_rejected():
    mgr = ConfirmationManager()
    with pytest.raises(ValueError):
        mgr.request("x", level="urgent")
    conf = mgr.request("x")
    with pytest.raises(ValueError):
        mgr.resolve(conf.confirmation_id, "maybe")


def test_unknown_confirmation_raises():
    mgr = ConfirmationManager()
    with pytest.raises(KeyError):
        mgr.executable("missing")
