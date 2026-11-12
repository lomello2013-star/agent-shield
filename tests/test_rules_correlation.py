"""Tests for multi-event correlation rules (stage 11 reflex correlation)."""

import pytest

from core.rules import Rule, RuleEngine, lint_rules


def rule(**overrides) -> Rule:
    base = dict(
        id="LINUX-EXEC-CORR-108",
        title="mprotect EXEC after a cross-process memory write",
        severity="high",
        technique="T1055",
        layer="L3",
        match={},
        reason_code="mprotect_after_injection",
        correlate={
            "window_sec": 5,
            "group_by": "actor.pid",
            "require": [
                {"category": "memory.access", "action": "mprotect_exec",
                 "platform_data.anon": True},
                {"category": "memory.access",
                 "action": {"regex": "(?i)(vm_write|ptrace|proc_mem)"}},
            ],
        },
    )
    base.update(overrides)
    return Rule(**base)


def make_event(**overrides):
    """Local builder mirroring tests/conftest.py (fixtures cannot be called directly)."""
    import copy
    import uuid
    from datetime import datetime, timezone
    from schemas.v3 import Event
    now = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
    payload = {
        "schema_version": "3.0", "event_id": str(uuid.uuid4()),
        "trace_id": str(uuid.uuid4()), "ts_event": now.isoformat(),
        "ts_ingest": now.isoformat(), "platform": "windows",
        "source": "win.etw.ti", "layer": "kernel",
        "category": "process.start", "action": "start",
        "actor": {"pid": 4242, "ppid": 1000, "name": "notepad.exe",
                  "path": r"C:\\Windows\\System32\\notepad.exe",
                  "cmdline_hash": "ab" * 32, "cmdline_redacted": "notepad.exe"},
        "object": {"type": "file", "path": r"C:\\Users\\public\\doc.txt"},
        "host": {"host_id": "host-1", "os": "windows", "version": "10.0.19045",
                 "arch": "x64"},
        "raw_ref": "raw/x.jsonl.zst#1", "platform_data": {},
    }
    def merge(base, over):
        out = copy.deepcopy(base)
        for k, v in over.items():
            out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
        return out
    return Event.model_validate(merge(payload, overrides))


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_correlation_fires_when_both_seen_in_window():
    clock = Clock()
    engine = RuleEngine(rules=[rule()], now_fn=clock)
    pid = {"actor": {"pid": 42}}
    assert engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                                      platform="linux", platform_data={"anon": True},
                                      **pid)) == []
    verdicts = engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                                          platform="linux", **pid))
    assert len(verdicts) == 1
    assert verdicts[0].severity == "high"
    assert verdicts[0].reason_code == "mprotect_after_injection"


def test_correlation_requires_window():
    clock = Clock()
    engine = RuleEngine(rules=[rule()], now_fn=clock)
    pid = {"actor": {"pid": 42}}
    engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                               platform="linux", platform_data={"anon": True}, **pid))
    clock.t += 6.0
    assert engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                                      platform="linux", **pid)) == []


def test_correlation_requires_same_group():
    clock = Clock()
    engine = RuleEngine(rules=[rule()], now_fn=clock)
    engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                               platform="linux", platform_data={"anon": True},
                               actor={"pid": 1}))
    assert engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                                      platform="linux", actor={"pid": 2})) == []


def test_correlation_needs_every_requirement():
    clock = Clock()
    engine = RuleEngine(rules=[rule()], now_fn=clock)
    for _ in range(5):
        assert engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                                          platform="linux", actor={"pid": 7})) == []


def test_correlation_does_not_storm():
    clock = Clock()
    engine = RuleEngine(rules=[rule()], now_fn=clock)
    pid = {"actor": {"pid": 9}}
    engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                               platform="linux", platform_data={"anon": True}, **pid))
    fired = 0
    for _ in range(5):
        fired += len(engine.evaluate(make_event(category="memory.access",
                                                action="process_vm_writev",
                                                platform="linux", **pid)))
        clock.t += 0.1
    assert fired == 1          # state cleared after firing


def test_correlation_ignores_non_anonymous_mprotect():
    clock = Clock()
    engine = RuleEngine(rules=[rule()], now_fn=clock)
    pid = {"actor": {"pid": 11}}
    engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                               platform="linux", platform_data={"anon": False}, **pid))
    assert engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                                      platform="linux", **pid)) == []


@pytest.mark.parametrize("bad", [
    {"require": [{"category": "memory.access"}]},                       # only one
    {"require": [], "window_sec": 5},                                   # empty
    {"require": [{"category": "memory.access"}, {"category": "file.exec"}],
     "window_sec": 0},                                                  # bad window
    {"require": [{"category": "memory.access"}, {"category": "file.exec"}],
     "window_sec": 5, "group_by": "nonsense.field"},                    # bad group
    {"require": [{"category": "memory.access"}, {"unknown.field": 1}],
     "window_sec": 5},                                                  # bad field
    {"require": [{"category": "memory.access"}, {"category": {"bad_op": 1}}],
     "window_sec": 5},                                                  # bad operator
])
def test_correlation_lint_rejects_bad_specs(bad):
    problems = lint_rules([rule(correlate=bad)])
    assert problems, "lint must reject the spec"



def tree_rule(**overrides) -> Rule:
    base = dict(
        id="LINUX-EXEC-CORR-109",
        title="mprotect EXEC in the process tree after a cross-process write",
        severity="high",
        technique="T1055",
        layer="L3",
        match={},
        reason_code="mprotect_after_injection_tree",
        correlate={
            "window_sec": 5,
            "group_by": "process_tree",
            "require": [
                {"category": "memory.access", "action": "mprotect_exec",
                 "platform_data.anon": True},
                {"category": "memory.access",
                 "action": {"regex": "(?i)(vm_write|ptrace|proc_mem)"}},
            ],
        },
    )
    base.update(overrides)
    return Rule(**base)


def test_tree_grouping_catches_parent_writing_child_executing():
    clock = Clock()
    engine = RuleEngine(rules=[tree_rule()], now_fn=clock)
    # parent writes into the child's memory
    engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                               platform="linux", actor={"pid": 500, "ppid": 1}))
    # the *child* adds PROT_EXEC to its own anonymous page
    verdicts = engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                                          platform="linux", platform_data={"anon": True},
                                          actor={"pid": 600, "ppid": 500}))
    assert len(verdicts) == 1
    assert verdicts[0].rule_id == "LINUX-EXEC-CORR-109"


def test_pid_grouping_misses_the_same_scenario():
    clock = Clock()
    engine = RuleEngine(rules=[rule()], now_fn=clock)     # group_by actor.pid
    engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                               platform="linux", actor={"pid": 500, "ppid": 1}))
    assert engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                                      platform="linux", platform_data={"anon": True},
                                      actor={"pid": 600, "ppid": 500})) == []


def test_tree_grouping_walks_multiple_levels():
    clock = Clock()
    engine = RuleEngine(rules=[tree_rule()], now_fn=clock)
    engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                               platform="linux", actor={"pid": 100, "ppid": 1}))
    engine.evaluate(make_event(category="file.exec", action="exec", platform="linux",
                               actor={"pid": 200, "ppid": 100}))
    verdicts = engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                                          platform="linux", platform_data={"anon": True},
                                          actor={"pid": 300, "ppid": 200}))
    assert len(verdicts) == 1


def test_tree_grouping_survives_cycles():
    clock = Clock()
    engine = RuleEngine(rules=[tree_rule()], now_fn=clock)
    engine.evaluate(make_event(category="file.exec", action="exec", platform="linux",
                               actor={"pid": 10, "ppid": 11}))
    engine.evaluate(make_event(category="file.exec", action="exec", platform="linux",
                               actor={"pid": 11, "ppid": 10}))
    assert engine._root_pid(10) in {"10", "11"}     # bounded, no hang


def test_provenance_rule_requires_known_path():
    """F03: an unresolved actor path must not produce the high-severity alert."""
    clock = Clock()
    engine = RuleEngine(rules=[tree_rule(), provenance_rule()], now_fn=clock)
    f = {"actor": {"pid": 900, "ppid": 1, "path": ""}}
    # unknown provenance: no CORR-110, only the (demoted) tree rule
    engine.evaluate(make_event(category="memory.access", action="process_vm_writev",
                               platform="linux", platform_data={"provenance_known": False}, **f))
    verdicts = engine.evaluate(make_event(category="memory.access", action="mprotect_exec",
                                          platform="linux", platform_data={"anon": True},
                                          actor={"pid": 901, "ppid": 900}))
    assert [v.rule_id for v in verdicts] == ["LINUX-EXEC-CORR-109"]


def provenance_rule() -> Rule:
    base = dict(
        id="LINUX-EXEC-CORR-110",
        title="PROT_EXEC after a cross-process write from an untrusted path",
        severity="high",
        technique="T1055",
        layer="L3",
        match={},
        reason_code="mprotect_after_injection_provenance",
        correlate={
            "window_sec": 5,
            "group_by": "process_tree",
            "require": [
                {"category": "memory.access", "action": "mprotect_exec",
                 "platform_data.anon": True},
                {"category": "memory.access",
                 "action": {"regex": "(?i)(vm_write|ptrace|proc_mem)"},
                 "actor.path": {"not_regex": "^/(usr|bin|sbin|opt|snap|nix)/"},
                 "platform_data.provenance_known": True},
            ],
        },
    )
    base.update({})
    return Rule(**base)
