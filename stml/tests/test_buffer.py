from stml.contracts.v0 import Priority, Report
from stml.connector.buffer import Spool


def _report(rid: str, priority: Priority = Priority.P2) -> Report:
    return Report(tenant_id="t", agent_id="a", connector_id="c",
                  message_id=rid, nonce="n" * 8, report_id=rid,
                  priority=priority, kind="test", payload={})


def test_duplicate_report_id_is_ignored(tmp_path):
    spool = Spool(tmp_path / "s.sqlite3")
    assert spool.enqueue(_report("r1"))
    assert not spool.enqueue(_report("r1"))
    assert spool.pending_count() == 1


def test_p0_ordered_first_and_acked(tmp_path):
    spool = Spool(tmp_path / "s.sqlite3")
    spool.enqueue(_report("p2", Priority.P2))
    spool.enqueue(_report("p0", Priority.P0))
    items = spool.peek()
    assert [i.report_id for i in items] == ["p0", "p2"]
    assert spool.ack(["p0", "p2"]) == 2
    assert spool.pending_count() == 0


def test_enforce_limit_never_drops_p0(tmp_path):
    spool = Spool(tmp_path / "s.sqlite3")
    spool.enqueue(_report("p0", Priority.P0))
    for i in range(5):
        spool.enqueue(_report(f"p2-{i}", Priority.P2))
    assert spool.enforce_limit(max_rows=2) == 3
    assert spool.p0_count() == 1
    assert spool.pending_count() == 3


def test_retry_backoff_delays(tmp_path):
    spool = Spool(tmp_path / "s.sqlite3")
    spool.enqueue(_report("r1"))
    item = spool.peek()[0]
    spool.mark_attempt(item.row_id, 1, delay_s=60)
    assert spool.peek(now=__import__("time").time() + 1) == []
