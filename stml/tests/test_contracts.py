from datetime import datetime

import pytest
from pydantic import ValidationError

from stml.contracts import v0


def test_heartbeat_roundtrip():
    hb = v0.Heartbeat(
        tenant_id="t1", agent_id="a1", connector_id="c1",
        message_id="m1", nonce="n" * 8, status=v0.AgentStatus.HEALTHY,
        health={"ok": True}, source="rpc",
    )
    raw = hb.model_dump_json()
    again = v0.Heartbeat.model_validate_json(raw)
    assert again.agent_id == "a1"
    assert again.status is v0.AgentStatus.HEALTHY


def test_naive_datetime_rejected():
    with pytest.raises(ValidationError):
        v0.Heartbeat(
            tenant_id="t1", agent_id="a1", connector_id="c1",
            message_id="m1", nonce="n" * 8, sent_at=datetime(2026, 1, 1),
            status=v0.AgentStatus.HEALTHY,
        )


def test_priority_enum_and_report_id_required():
    report = v0.Report(
        tenant_id="t1", agent_id="a1", connector_id="c1",
        message_id="m1", nonce="n" * 8, report_id="r1",
        priority=v0.Priority.P0, kind="incident", payload={"x": 1},
    )
    assert report.priority is v0.Priority.P0
    with pytest.raises(ValidationError):
        v0.Report(
            tenant_id="t1", agent_id="a1", connector_id="c1",
            message_id="m1", nonce="n" * 8, priority=v0.Priority.P0, kind="x",
        )
