import pytest

from core.rules import Rule, RuleEngine, lint_rules, load_rules, rule_matches
from rules_cases import RULE_CASES

RULES = load_rules(["rules/base.json"])
BY_ID = {r.id: r for r in RULES}


def build(engine, make_event, rule_id):
    case = RULE_CASES[rule_id]
    events = []
    for overrides in case["events"]:
        events.append(make_event(**overrides))
    verdicts = []
    for ev in events:
        verdicts.extend(engine.evaluate(ev))
    return verdicts


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
def test_rule_detects_its_scenario(rule_id, make_event):
    engine = RuleEngine([BY_ID[rule_id]])
    verdicts = build(engine, make_event, rule_id)
    hits = [v for v in verdicts if v.rule_id == rule_id]
    assert hits, f"{rule_id} did not fire on its own fixture"
    rule = BY_ID[rule_id]
    assert hits[0].severity == rule.severity
    assert hits[0].detector == "rule"
    assert hits[0].reason_code == rule.reason_code
    assert hits[0].confidence == 1.0


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
def test_rule_ignores_benign_control(rule_id, make_event):
    """Every rule must stay quiet on a benign control event (no blanket matches)."""
    engine = RuleEngine([BY_ID[rule_id]])
    benign = make_event()
    assert engine.evaluate(benign) == [], f"{rule_id} fired on benign control"


def test_benign_process_start_produces_no_verdict(make_event):
    engine = RuleEngine(RULES)
    assert engine.evaluate(make_event()) == []


def test_lsass_access_alerts_with_critical_severity(make_event):
    ev = make_event(category="process.access", action="open_process",
                    object={"type": "process", "path": r"C:\Windows\System32\lsass.exe"})
    verdicts = RuleEngine(RULES).evaluate(ev)
    assert any(v.rule_id == "WIN-LSASS-ACCESS-004" and v.severity == "critical" for v in verdicts)


def test_windowed_rule_fires_only_at_threshold(make_event):
    rule = BY_ID["FILE-MASS-WRITE-014"]
    now = [1000.0]
    engine = RuleEngine([rule], now_fn=lambda: now[0])
    verdicts = []
    for i in range(49):
        verdicts += engine.evaluate(make_event(category="file.write", action="write"))
    assert verdicts == []
    verdicts += engine.evaluate(make_event(category="file.write", action="write"))
    assert len(verdicts) == 1                       # 50th write fires


def test_window_expires_old_events(make_event):
    rule = BY_ID["FILE-MASS-WRITE-014"]
    now = [1000.0]
    engine = RuleEngine([rule], now_fn=lambda: now[0])
    for _ in range(30):
        engine.evaluate(make_event(category="file.write"))
    now[0] += 20                                     # window is 10 s
    for _ in range(30):
        engine.evaluate(make_event(category="file.write"))
    assert engine.counts().get("FILE-MASS-WRITE-014", 0) == 0


def test_engine_rejects_invalid_rules():
    bad = Rule(id="x", title="t", severity="high", technique="T1059", layer="L2",
               match={"nope": 1}, reason_code="r")
    with pytest.raises(ValueError):
        RuleEngine([bad])


def test_lint_catches_duplicates_and_bad_fields():
    good = Rule(id="R-1", title="t", severity="high", technique="T1059", layer="L2",
                match={"category": "process.start"}, reason_code="r")
    dup = Rule(id="R-1", title="t2", severity="high", technique="T1059", layer="L2",
               match={"category": "process.start"}, reason_code="r")
    problems = lint_rules([good, dup])
    assert any("duplicate" in p for p in problems)

    bad_field = Rule(id="R-2", title="t", severity="high", technique="T1059", layer="L2",
                     match={"actor.nonexistent": "x"}, reason_code="r")
    assert any("unknown field" in p for p in lint_rules([bad_field]))

    bad_sev = Rule(id="R-3", title="t", severity="urgent", technique="T1059", layer="L2",
                   match={"category": "process.start"}, reason_code="r")
    assert any("severity" in p for p in lint_rules([bad_sev]))

    bad_regex = Rule(id="R-4", title="t", severity="high", technique="T1059", layer="L2",
                     match={"actor.path": {"regex": "("}}, reason_code="r")
    assert any("regex" in p for p in lint_rules([bad_regex]))


def test_lint_catches_bad_window_configuration():
    r = Rule(id="R-5", title="t", severity="high", technique="T1486", layer="L6",
             match={"category": "file.write"}, reason_code="r", window_sec=5)
    assert any("window_sec" in p for p in lint_rules([r]))


def test_lint_catches_unknown_technique_against_matrix():
    r = Rule(id="R-6", title="t", severity="high", technique="T9999", layer="L2",
             match={"category": "process.start"}, reason_code="r")
    problems = lint_rules([r], known_techniques={"T1059"})
    assert any("not in coverage matrix" in p for p in problems)


def test_rule_matches_is_conjunctive(make_event):
    rule = BY_ID["WIN-PS-ENCODED-002"]
    ps = {"name": "powershell.exe",
          "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}
    ev = make_event(actor=ps, platform_data={"cmdline": "powershell -enc AAAA"})
    assert rule_matches(rule, ev.model_dump(mode="json"))
    ev2 = make_event(actor=ps, platform_data={"cmdline": "powershell -file a.ps1"})
    assert not rule_matches(rule, ev2.model_dump(mode="json"))


def test_disabled_rule_is_not_evaluated(make_event):
    rule = BY_ID["WIN-LOG-CLEAR-008"]
    rule.enabled = False
    engine = RuleEngine([rule])
    assert engine.evaluate(make_event(category="log.tamper")) == []


def test_negative_operators():
    from core.rules import _match_condition
    assert _match_condition("/tmp/x", {"not_regex": "^/(usr|bin)/"})
    assert not _match_condition("/usr/bin/x", {"not_regex": "^/(usr|bin)/"})
    assert _match_condition("/tmp/x", {"not_startswith": "/usr"})
    assert not _match_condition("/usr/x", {"not_startswith": "/usr"})
    assert _match_condition("hello", {"not_contains": "evil"})
    assert not _match_condition("hello evil", {"not_contains": "evil"})
    assert not _match_condition(None, {"not_regex": "x"})


GLOBAL_RULES_JUSTIFIED = {
    # network and file behaviours that are identical on both platforms; the platform
    # is expressed by the event source, not by the rule
    "NET-SMB-LATERAL-012", "NET-DNS-LONG-013", "NET-EXFIL-LARGE-017",
    "FILE-MASS-WRITE-014", "FILE-CANARY-015",
}


def test_every_rule_is_platform_scoped_or_justified_global():
    """F18: a rule must not silently apply to the wrong OS (this bug happened once)."""
    for rule in RULES:
        match_platform = rule.match.get("platform")
        if rule.id.startswith("WIN-"):
            assert match_platform == "windows", f"{rule.id} must be windows-only"
        elif rule.id.startswith("LINUX-"):
            if rule.correlate:
                require = rule.correlate.get("require", [])
                assert require, f"{rule.id} correlation has no requirements"
                assert all(req.get("platform") == "linux" for req in require), (
                    f"{rule.id} correlation must be linux-only")
            else:
                assert match_platform == "linux", f"{rule.id} must be linux-only"
        else:
            assert rule.id in GLOBAL_RULES_JUSTIFIED, (
                f"{rule.id} is neither platform-scoped nor in the justified global set")
