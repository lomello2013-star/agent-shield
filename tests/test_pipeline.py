import uuid
from datetime import datetime, timezone

import pytest

from core.ingest import P0_PROCESS, P1_FILE, P2_NOISE, IngestPipeline
from core.normalize import HostContext, Normalizer
from core.pipeline import Pipeline, priority_for
from core.rules import RuleEngine, load_rules

NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
RULES = load_rules(["rules/base.json"])


def make_pipeline(tmp_path=None):
    host = HostContext(host_id="host-1", os="windows", version="10.0.19045", arch="x64")
    norm = Normalizer(host=host, now_fn=lambda: NOW,
                      quarantine_path=str(tmp_path / "q.jsonl") if tmp_path else None)
    ingest = IngestPipeline(capacity=1000, spill_path=None)
    return Pipeline(normalizer=norm, ingest=ingest, engine=RuleEngine(RULES))


def etw(**overrides):
    raw = {"process_id": 512, "parent_id": 4, "process_name": r"C:\Temp\x.exe",
           "cmdline": "x.exe", "target": r"C:\Windows\System32\lsass.exe",
           "category": "process.access", "action": "open_process"}
    raw.update(overrides)
    return raw


def test_priority_mapping_follows_reliability_order():
    assert priority_for("process.start") == P0_PROCESS
    assert priority_for("priv.grant") == P0_PROCESS
    assert priority_for("file.write") == P1_FILE
    assert priority_for("file.read") == P1_FILE
    assert priority_for("net.connect") == P1_FILE
    assert priority_for("auth.failure") == P2_NOISE
    assert priority_for("totally.unknown") == P2_NOISE


def test_end_to_end_lsass_verdict():
    pipe = make_pipeline()
    assert pipe.submit_raw("win.etw.ti", etw()) is True
    verdicts = pipe.run_once()
    assert [v.rule_id for v in verdicts] == ["WIN-LSASS-ACCESS-004"]
    assert pipe.stats()["verdicts"] == 1


def test_invalid_raw_is_quarantined_not_crashing(tmp_path):
    pipe = make_pipeline(tmp_path)
    assert pipe.submit_raw("win.etw.ti", {"process_id": 1}) is False
    assert pipe.rejected == 1
    assert pipe.ingest.received == 0
    assert pipe.normalizer.stats()["quarantined"] == 1
    assert (tmp_path / "q.jsonl").exists()


def test_unknown_source_is_rejected():
    pipe = make_pipeline()
    assert pipe.submit_raw("macos.endpoint", {}) is False
    assert pipe.rejected == 1


def test_p0_events_precede_noise_in_drain():
    pipe = make_pipeline()
    for i in range(20):
        pipe.submit_raw("win.etw.ti", etw(process_id=100 + i, target=r"C:\a.txt",
                                          category="file.write", action="write"))
    pipe.run_once(max_events=0)  # drain nothing (max_events=0 means unlimited per ingest)
    pipe.ingest.drain(1000)      # clear
    for i in range(20):
        pipe.submit_raw("win.etw.ti", etw(process_id=200 + i, target=r"C:\a.txt",
                                          category="file.write", action="write"))
    pipe.submit_raw("win.etw.ti", etw(process_id=999))
    records = pipe.ingest.drain(5)
    assert records[0].payload["category"] == "process.access"


def test_storm_has_no_silent_loss(tmp_path):
    pipe = make_pipeline(tmp_path)
    pipe.ingest = IngestPipeline(capacity=200, reserved_ratio=0.2,
                                 spill_path=str(tmp_path / "spill.jsonl"))
    total = 1500
    for i in range(total):
        if i % 10 == 0:
            pipe.submit_raw("win.etw.ti", etw(process_id=i))
        elif i % 3 == 0:
            pipe.submit_raw("win.etw.ti", etw(process_id=i, category="file.write",
                                              action="write", target=r"C:\f.txt"))
        else:
            pipe.submit_raw("win.amsi", {"app_name": r"C:\ps.exe", "content_name": "sb",
                                         "result": 1, "process_id": i})
    drained = 0
    while True:
        chunk = pipe.ingest.drain(500)
        if not chunk:
            break
        drained += len(chunk)
    assert pipe.ingest.lost == 0
    assert pipe.ingest.ledger_ok()
    assert pipe.ingest.received == total
    assert pipe.rejected == 0


def test_verdict_sink_receives_verdicts():
    seen = []
    pipe = make_pipeline()
    pipe.on_verdict = seen.append
    pipe.submit_raw("win.etw.ti", etw())
    pipe.run_once()
    assert len(seen) == 1 and seen[0].rule_id == "WIN-LSASS-ACCESS-004"


def test_stats_expose_all_stages():
    pipe = make_pipeline()
    pipe.submit_raw("win.etw.ti", etw())
    pipe.run_once()
    stats = pipe.stats()
    assert set(stats) == {"ingest", "normalizer", "rejected", "verdicts", "rule_counts"}
    assert stats["rule_counts"]["WIN-LSASS-ACCESS-004"] == 1


def test_live_event_is_not_validated_twice(tmp_path):
    """F11: the event validated on submit must not be re-validated in run_once."""
    from unittest import mock

    from core.ingest import IngestPipeline
    from core.normalize import HostContext, Normalizer
    from core.rules import RuleEngine, load_rules
    from core.pipeline import Pipeline
    from schemas.v3 import Event

    host = HostContext(host_id="h", os="windows", version="10", arch="x64")
    pipe = Pipeline(normalizer=Normalizer(host=host),
                    ingest=IngestPipeline(capacity=100),
                    engine=RuleEngine(load_rules(["rules/base.json"])))
    assert pipe.submit_raw("win.etw.ti", etw()) is True

    real_validate = Event.model_validate
    calls = {"n": 0}

    def counting(value):
        calls["n"] += 1
        return real_validate(value)

    with mock.patch.object(Event, "model_validate", staticmethod(counting)):
        pipe.run_once()

    assert calls["n"] == 0, "live record must reuse the validated event"
