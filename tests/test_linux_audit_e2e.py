"""End-to-end: Linux auditd -> daemon report file -> connector spool/transport."""

from __future__ import annotations

import json

from core.auditsource import LinuxAuditSource
from core.daemon import Daemon, DaemonConfig
from core.normalize import HostContext
from stml.connector.buffer import Spool
from stml.connector.jsonl_tail import JsonlTailer
from stml.connector.service import Connector, ConnectorConfig
from stml.connector.transport import MemoryTransport
from tests.test_auditsource import _lines

HOST = HostContext(host_id="linux-h", os="linux", version="6.8", arch="x64")


def _audit_file(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("\n".join(_lines()) + "\n", encoding="utf-8")
    return path


def test_daemon_writes_normalized_audit_events_for_connector(tmp_path):
    path = _audit_file(tmp_path)
    cfg = DaemonConfig(sources=["linux.auditd"], audit_log_path=str(path),
                       event_reports=True)
    d = Daemon(str(tmp_path / "daemon"), config=cfg, host=HOST,
               collectors=[LinuxAuditSource(str(path), flush_after_s=0)])
    try:
        assert d.collect_once() == 3
        assert d.pipeline.ingest.received == 3
        d.tick()
    finally:
        d.stop()

    report_path = tmp_path / "daemon" / "reports" / "events.jsonl"
    records = [json.loads(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 3
    assert records[0]["kind"] == "event"
    assert records[0]["priority"] == "P1"
    assert records[0]["event"]["platform"] == "linux"
    assert records[0]["event"]["source"] == "linux.auditd"
    assert records[0]["event"]["actor"]["pid"] == 4242


def test_connector_delivers_audit_events(tmp_path):
    path = _audit_file(tmp_path)
    cfg = DaemonConfig(sources=["linux.auditd"], audit_log_path=str(path),
                       event_reports=True)
    d = Daemon(str(tmp_path / "daemon"), config=cfg, host=HOST,
               collectors=[LinuxAuditSource(str(path), flush_after_s=0)])
    try:
        d.collect_once()
    finally:
        d.stop()

    transport = MemoryTransport()
    ccfg = ConnectorConfig(tenant_id="t", data_root=str(tmp_path / "daemon"),
                           spool_path=str(tmp_path / "spool.sqlite3"),
                           state_path=str(tmp_path / "state.json"))
    connector = Connector(ccfg, None, Spool(ccfg.spool_path),
                          JsonlTailer(tmp_path / "tail.json"), transport)
    connector.tick()
    events = [r for r in transport.sent if r.kind == "event"]
    assert len(events) == 3
    assert all(r.payload["event"]["platform"] == "linux" for r in events)
    assert connector.last_error is None
