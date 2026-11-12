import pytest

from core.ingest import P0_PROCESS, P1_FILE, P2_NOISE, IngestPipeline


def drain_all(pipe, batch=100):
    out = []
    while True:
        pipe.flush_aggregation(force=True)
        chunk = pipe.drain(batch)
        if not chunk:
            break
        out.extend(chunk)
    return out


def test_priority_order_process_before_files():
    pipe = IngestPipeline(capacity=100)
    pipe.submit("file.write", "f1", priority=P1_FILE)
    pipe.submit("process.start", "p1", priority=P0_PROCESS)
    pipe.submit("file.write", "f2", priority=P1_FILE)
    got = pipe.drain(10)
    assert [r.category for r in got] == ["process.start", "file.write", "file.write"]


def test_noise_is_aggregated_not_queued_per_event():
    pipe = IngestPipeline(capacity=100, aggregation_window_s=60)
    for _ in range(50):
        assert pipe.submit("auth.failure", "same-key", priority=P2_NOISE)
    stats = pipe.stats()
    assert stats["queues"]["noise"] == 0          # still in aggregation bucket
    assert stats["aggregated"] == 49
    pipe.flush_aggregation(force=True)            # window not elapsed yet
    got = pipe.drain(10)
    assert len(got) == 1 and got[0].count == 50
    assert pipe.stats()["delivered"] == 50
    assert pipe.ledger_ok()


def test_aggregation_window_expiry_flushes_bucket():
    now = [0.0]
    pipe = IngestPipeline(capacity=10, aggregation_window_s=1.0, now_fn=lambda: now[0])
    pipe.submit("net.connect", "k", priority=P2_NOISE)
    now[0] = 0.5
    pipe.submit("net.connect", "k", priority=P2_NOISE)
    assert pipe.stats()["queues"]["noise"] == 0
    now[0] = 2.0
    pipe.submit("net.connect", "k", priority=P2_NOISE)   # expires old bucket first
    got = pipe.drain(10)
    assert got[0].count == 2      # first two aggregated
    assert pipe.ledger_ok()


def test_spill_to_disk_and_replay(tmp_path):
    spill = tmp_path / "spool" / "events.jsonl"
    pipe = IngestPipeline(capacity=4, reserved_ratio=0.0, spill_path=str(spill))
    for i in range(10):
        pipe.submit("file.create", f"k{i}", priority=P1_FILE)
    assert pipe.spilled > 0
    got = drain_all(pipe)
    assert pipe.lost == 0
    assert pipe.received == 10 == pipe.delivered
    assert pipe.ledger_ok()
    assert not spill.exists()          # spool consumed
    assert len(got) == 10


def test_loss_is_counted_and_incident_raised_when_no_spill():
    incidents = []
    pipe = IngestPipeline(capacity=2, reserved_ratio=0.0, on_incident=incidents.append)
    for i in range(5):
        pipe.submit("file.write", f"k{i}", priority=P1_FILE)
    assert pipe.lost == 3
    assert incidents, "loss must raise an incident, never be silent"
    assert pipe.stats()["lost"] == 3
    assert pipe.ledger_ok()


def test_p0_reserved_headroom_survives_noise_storm():
    """P1/P2 cannot consume the reserved tail; P0 still gets through."""
    pipe = IngestPipeline(capacity=10, reserved_ratio=0.3)
    for i in range(20):
        pipe.submit("file.write", f"f{i}", priority=P1_FILE)
    assert pipe.submit("process.start", "critical", priority=P0_PROCESS)
    got = pipe.drain(100)
    assert any(r.category == "process.start" for r in got)
    assert pipe.ledger_ok()


def test_ledger_invariant_under_mixed_storm(tmp_path):
    spill = tmp_path / "spool.jsonl"
    pipe = IngestPipeline(capacity=64, reserved_ratio=0.25, spill_path=str(spill),
                          aggregation_window_s=0.0)
    for i in range(1500):
        if i % 10 == 0:
            pipe.submit("process.start", f"p{i}", priority=P0_PROCESS)
        elif i % 3 == 0:
            pipe.submit("file.write", f"f{i}", priority=P1_FILE)
        else:
            pipe.submit("auth.failure", "noise", priority=P2_NOISE)
    got = drain_all(pipe, batch=200)
    assert pipe.flush_aggregation(force=True) >= 0
    got += drain_all(pipe, batch=200)
    assert pipe.ledger_ok(), pipe.stats()
    assert pipe.lost == 0
    assert pipe.delivered == pipe.received
    assert pipe.loss_ratio() == 0.0


def test_bad_priority_rejected():
    with pytest.raises(ValueError):
        IngestPipeline().submit("x", priority=99)


def test_backlog_gauge_tracks_queue_depth():
    pipe = IngestPipeline(capacity=100)
    pipe.submit("process.start", "a", priority=P0_PROCESS)
    assert pipe.stats()["backlog"] == 1
    pipe.drain(1)
    assert pipe.stats()["backlog"] == 0

