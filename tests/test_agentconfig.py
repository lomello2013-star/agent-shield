"""Agent TOML config: file, thresholds, env overrides, validation."""

from __future__ import annotations

import pytest

from core.agentconfig import AgentConfig, load_agent_config


def test_loads_toml_and_builds_daemon_config(tmp_path):
    path = tmp_path / "agent.toml"
    path.write_text("""
[agent]
source = "linux.auditd"
audit_log = "/tmp/audit.log"
data_root = "/tmp/aidf"
report_events = false
collect_interval_s = 2.5
queue_capacity = 77

[thresholds]
heartbeat_timeout_s = 12
alert_budget = 3
min_confidence = 0.7

[stml]
server_url = "http://example:8080"
tenant = "t1"
""", encoding="utf-8")
    cfg = load_agent_config(path)
    assert cfg.source == "linux.auditd"
    assert cfg.audit_log == "/tmp/audit.log"
    assert cfg.report_events is False
    assert cfg.collect_interval_s == 2.5
    assert cfg.heartbeat_timeout_s == 12
    assert cfg.alert_budget == 3
    assert cfg.min_confidence == 0.7
    assert cfg.server_url == "http://example:8080"
    dc = cfg.to_daemon_config()
    assert dc.sources == ["linux.auditd"]
    assert dc.audit_log_path == "/tmp/audit.log"
    assert dc.event_reports is False
    assert dc.queue["capacity"] == 77


def test_env_overrides_file(monkeypatch, tmp_path):
    path = tmp_path / "agent.toml"
    path.write_text('[agent]\nsource = "linux.auditd"\naudit_log = "/a"\n',
                    encoding="utf-8")
    monkeypatch.setenv("AIDF_AUDIT_LOG", "/b")
    monkeypatch.setenv("AIDF_DATA", "/data")
    monkeypatch.setenv("AIDF_SOURCE", "linux.ebpf")
    cfg = load_agent_config(path)
    assert cfg.audit_log == "/b"
    assert cfg.data_root == "/data"
    assert cfg.source == "linux.ebpf"


def test_rejects_bad_values(tmp_path):
    path = tmp_path / "agent.toml"
    path.write_text("[agent]\ncollect_interval_s = 0\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_agent_config(path)

    path.write_text("[thresholds]\nmin_confidence = 2\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_agent_config(path)


def test_missing_file_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_agent_config(tmp_path / "nope.toml")
