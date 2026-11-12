"""Update gate tests for F12b: critical verdicts bypass the alert budget."""

import io

PATH = "tests/test_gate.py"
text = io.open(PATH, encoding="utf-8").read()

old_1 = '''def test_critical_verdict_proposes_reversible_actions_and_alerts():
    gate = PolicyGate()
    decision = gate.decide(verdict("critical"), "h1", "pid:1")
    assert decision.actions == ("quarantine", "suspend")
    assert decision.alert is True and decision.reason == "alert_and_contain"'''
new_1 = '''def test_critical_verdict_proposes_reversible_actions_and_alerts():
    gate = PolicyGate()
    decision = gate.decide(verdict("critical"), "h1", "pid:1")
    assert decision.actions == ("quarantine", "suspend")
    # F12b: critical is never muted by the budget, so the reason is the bypass.
    assert decision.alert is True and decision.reason == "critical_bypass"'''
if old_1 not in text:
    raise SystemExit("critical test anchor not found")
text = text.replace(old_1, new_1, 1)

old_2 = '''def test_budget_exhaustion_contains_without_alert():
    gate = PolicyGate(budget=AlertBudget(per_window=1, window_s=1000))
    first = gate.decide(verdict("critical"), "h1", "pid:1")
    second = gate.decide(verdict("critical"), "h1", "pid:2")
    assert first.alert is True
    assert second.alert is False and second.reason == "contain_without_alert"
    assert second.actions == ("quarantine", "suspend")     # containment still happens'''
new_2 = '''def test_budget_exhaustion_contains_without_alert():
    # high severity is the budgeted case; critical has its own bypass (F12b)
    gate = PolicyGate(budget=AlertBudget(per_window=1, window_s=1000))
    first = gate.decide(verdict("high"), "h1", "pid:1")
    second = gate.decide(verdict("high"), "h1", "pid:2")
    assert first.alert is True
    assert second.alert is False and second.reason == "contain_without_alert"
    assert second.actions == ("suspend",)                  # containment still happens'''
if old_2 not in text:
    raise SystemExit("budget test anchor not found")
text = text.replace(old_2, new_2, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("tests updated")
