import uuid

import pytest

from core.gate import AlertBudget, PolicyGate, SuppressionList, ppv


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def verdict(severity="high", confidence=1.0, rule_id="R-1"):
    return __import__("schemas.v3", fromlist=["Verdict"]).Verdict.model_validate({
        "verdict_id": str(uuid.uuid4()), "trace_id": str(uuid.uuid4()),
        "event_id": str(uuid.uuid4()), "detector": "rule", "rule_id": rule_id,
        "platform": "windows", "confidence": confidence, "severity": severity,
        "reason_code": "rc", "reason_text": "rt",
    })


# ------------------------------------------------------------------------ PPV
def test_ppv_matches_formula():
    assert ppv(1.0, 0.0, 0.001) == 1.0
    assert ppv(0.0, 1.0, 0.001) == 0.0
    # measured-style numbers: 87% TPR at 1% FPR, prevalence 1/1000
    value = ppv(0.87, 0.01, 0.001)
    assert 0.07 < value < 0.09


def test_ppv_rejects_bad_ranges():
    with pytest.raises(ValueError):
        ppv(1.5, 0.0, 0.001)
    with pytest.raises(ValueError):
        ppv(0.9, 0.1, 2.0)


# ---------------------------------------------------------------------- budget
def test_budget_limits_alerts_in_window():
    clock = FakeClock()
    budget = AlertBudget(per_window=1, window_s=100, now_fn=clock)
    assert budget.take("h1") is True
    assert budget.take("h1") is False
    assert budget.used("h1") == 1
    clock.t += 101
    assert budget.take("h1") is True


def test_budget_is_per_host():
    budget = AlertBudget(per_window=1, window_s=100)
    assert budget.take("h1") and budget.take("h2")


# ----------------------------------------------------------------- suppression
def test_suppression_expires():
    clock = FakeClock()
    sup = SuppressionList(ttl_s=50, now_fn=clock)
    sup.add("R-1", "pid:42")
    assert sup.is_suppressed("R-1", "pid:42") is True
    clock.t += 51
    assert sup.is_suppressed("R-1", "pid:42") is False
    assert sup.count() == 0


# ----------------------------------------------------------------------- gate
def test_critical_verdict_proposes_reversible_actions_and_alerts():
    gate = PolicyGate()
    decision = gate.decide(verdict("critical"), "h1", "pid:1")
    assert decision.actions == ("quarantine", "suspend")
    # F12b: critical is never muted by the budget, so the reason is the bypass.
    assert decision.alert is True and decision.reason == "critical_bypass"


def test_medium_severity_is_observe_only():
    decision = PolicyGate().decide(verdict("medium"), "h1", "pid:1")
    assert decision.actions == () and decision.alert is False
    assert decision.reason == "observe_only"


def test_high_severity_suspends_without_quarantine():
    decision = PolicyGate().decide(verdict("high"), "h1", "pid:1")
    assert decision.actions == ("suspend",)


def test_low_confidence_blocks_actions():
    decision = PolicyGate(min_confidence=0.8).decide(verdict("critical", confidence=0.4), "h1")
    assert decision.actions == () and decision.reason == "low_confidence"


def test_budget_exhaustion_contains_without_alert():
    # high severity is the budgeted case; critical has its own bypass (F12b)
    gate = PolicyGate(budget=AlertBudget(per_window=1, window_s=1000))
    first = gate.decide(verdict("high"), "h1", "pid:1")
    second = gate.decide(verdict("high"), "h1", "pid:2")
    assert first.alert is True
    assert second.alert is False and second.reason == "contain_without_alert"
    assert second.actions == ("suspend",)                  # containment still happens


def test_suppression_prevents_repeat_alerts():
    gate = PolicyGate()
    gate.approve_for_suppression(verdict("high", rule_id="R-9"), "pid:7")
    decision = gate.decide(verdict("high", rule_id="R-9"), "h1", "pid:7")
    assert decision.alert is False and decision.suppressed is True
    assert decision.actions == ()


def test_kill_switch_drops_rule_entirely():
    gate = PolicyGate(killed_rules={"R-1"})
    decision = gate.decide(verdict("critical", rule_id="R-1"), "h1")
    assert decision.actions == () and decision.reason == "kill_switch"


def test_model_verdicts_are_shadow_only():
    model_verdict = __import__("schemas.v3", fromlist=["Verdict"]).Verdict.model_validate({
        "verdict_id": str(uuid.uuid4()), "trace_id": str(uuid.uuid4()),
        "event_id": str(uuid.uuid4()), "detector": "file_model", "model_id": "pe",
        "platform": "windows", "confidence": 0.99, "severity": "critical",
        "reason_code": "ml", "reason_text": "shadow",
    })
    decision = PolicyGate().decide(model_verdict, "h1", "C:\\x.exe")
    assert decision.actions == () and decision.reason == "shadow_only"


def test_gate_stats_report_budget_and_suppressions():
    gate = PolicyGate(budget=AlertBudget(per_window=2, window_s=1000))
    gate.decide(verdict("high"), "h1", "pid:1")
    gate.approve_for_suppression(verdict("high", rule_id="R-2"), "pid:2")
    stats = gate.stats("h1")
    assert stats["budget_used"] == 1 and stats["budget_remaining"] == 1
    assert stats["suppressions"] == 1


# ------------------------------------------- F02/F03: signal vs alert levels
def test_low_severity_signal_never_alerts():
    """CORR-109 was demoted to low: the gate must observe, not alert."""
    gate = PolicyGate(budget=AlertBudget(per_window=10, window_s=100))
    decision = gate.decide(verdict(severity="low", rule_id="LINUX-EXEC-CORR-109"), "h1")
    assert decision.alert is False
    assert decision.actions == ()
    assert decision.reason == "observe_only"


def test_high_severity_provenance_rule_alerts():
    gate = PolicyGate(budget=AlertBudget(per_window=10, window_s=100))
    decision = gate.decide(verdict(severity="high", rule_id="LINUX-EXEC-CORR-110"), "h1")
    assert decision.alert is True
    assert decision.actions == ("suspend",)


# ------------------------------------------- F12b: critical bypasses the alert budget
def test_critical_alerts_even_when_budget_is_spent():
    clock = FakeClock()
    budget = AlertBudget(per_window=1, window_s=1000, now_fn=clock)
    gate = PolicyGate(budget=budget)
    # spend the only slot on a high-severity finding
    first = gate.decide(verdict(severity="high", rule_id="R-1"), "h1")
    assert first.alert is True
    # a critical finding must still alert (and contain)
    critical = gate.decide(verdict(severity="critical", rule_id="FILE-CANARY-015"), "h1")
    assert critical.alert is True
    assert critical.reason == "critical_bypass"
    assert "quarantine" in critical.actions


def test_high_is_still_budgeted_after_critical():
    clock = FakeClock()
    budget = AlertBudget(per_window=1, window_s=1000, now_fn=clock)
    gate = PolicyGate(budget=budget)
    gate.decide(verdict(severity="critical", rule_id="C-1"), "h1")
    decision = gate.decide(verdict(severity="high", rule_id="H-1"), "h1")
    assert decision.alert is False
    assert decision.actions == ("suspend",)      # contained, but not announced


def test_critical_bypass_can_be_disabled():
    clock = FakeClock()
    budget = AlertBudget(per_window=1, window_s=1000, now_fn=clock)
    gate = PolicyGate(budget=budget, critical_bypass_budget=False)
    gate.decide(verdict(severity="high", rule_id="R-1"), "h1")
    decision = gate.decide(verdict(severity="critical", rule_id="C-1"), "h1")
    assert decision.alert is False
