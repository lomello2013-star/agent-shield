"""Agent configuration: one TOML file for source, paths and thresholds.

The file is intentionally boring so it can be shipped by a package and edited by
an operator without touching code. Environment variables override the file for
containers and systemd drop-ins.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - older Python
    import tomli as tomllib  # type: ignore

from core.daemon import DaemonConfig


@dataclass
class AgentConfig:
    source: str = "linux.auditd"
    audit_log: str = "/var/log/audit/audit.log"
    data_root: str = "/var/lib/aidf"
    rules_path: str = ""
    report_events: bool = True
    collect_interval_s: float = 1.0
    queue_capacity: int = 10_000
    heartbeat_timeout_s: float = 60.0
    alert_budget: int = 1
    min_confidence: float = 0.5
    host_id: str = ""
    gui_host: str = "127.0.0.1"
    gui_port: int = 18080
    # STML endpoint is consumed by the connector; kept here so one file describes
    # the deployment. The agent itself never talks to the network.
    server_url: str = ""
    tenant: str = "default"
    enrol_token_file: str = ""
    tokens_file: str = ""

    def to_daemon_config(self) -> DaemonConfig:
        return DaemonConfig(
            sources=[self.source],
            audit_log_path=self.audit_log,
            event_reports=self.report_events,
            queue={"capacity": int(self.queue_capacity)},
            thresholds={
                "heartbeat_timeout_s": float(self.heartbeat_timeout_s),
                "alert_budget": int(self.alert_budget),
                "min_confidence": float(self.min_confidence),
            },
        )


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    return value if isinstance(value, dict) else {}


def load_agent_config(path: str | os.PathLike | None = None) -> AgentConfig:
    cfg = AgentConfig()
    if path:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(str(p))
        with p.open("rb") as fh:
            raw = fh.read()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]                 # Windows editors may add a UTF-8 BOM
        data = tomllib.loads(raw.decode("utf-8"))
        agent = _section(data, "agent")
        thresholds = _section(data, "thresholds")
        stml = _section(data, "stml")
        if "source" in agent:
            cfg.source = str(agent["source"])
        if "audit_log" in agent:
            cfg.audit_log = str(agent["audit_log"])
        if "data_root" in agent:
            cfg.data_root = str(agent["data_root"])
        if "rules_path" in agent:
            cfg.rules_path = str(agent["rules_path"])
        if "report_events" in agent:
            cfg.report_events = bool(agent["report_events"])
        if "collect_interval_s" in agent:
            cfg.collect_interval_s = float(agent["collect_interval_s"])
        if "host_id" in agent:
            cfg.host_id = str(agent["host_id"])
        if "gui_host" in agent:
            cfg.gui_host = str(agent["gui_host"])
        if "gui_port" in agent:
            cfg.gui_port = int(agent["gui_port"])
        if "queue_capacity" in agent:
            cfg.queue_capacity = int(agent["queue_capacity"])
        if "heartbeat_timeout_s" in thresholds:
            cfg.heartbeat_timeout_s = float(thresholds["heartbeat_timeout_s"])
        if "alert_budget" in thresholds:
            cfg.alert_budget = int(thresholds["alert_budget"])
        if "min_confidence" in thresholds:
            cfg.min_confidence = float(thresholds["min_confidence"])
        if "server_url" in stml:
            cfg.server_url = str(stml["server_url"])
        if "tenant" in stml:
            cfg.tenant = str(stml["tenant"])
        if "enrol_token_file" in stml:
            cfg.enrol_token_file = str(stml["enrol_token_file"])
        if "tokens_file" in stml:
            cfg.tokens_file = str(stml["tokens_file"])

    # Environment wins; this is how systemd/container deployments override paths.
    cfg.source = os.environ.get("AIDF_SOURCE", cfg.source)
    cfg.audit_log = os.environ.get("AIDF_AUDIT_LOG", cfg.audit_log)
    cfg.data_root = os.environ.get("AIDF_DATA", cfg.data_root)
    cfg.rules_path = os.environ.get("AIDF_RULES", cfg.rules_path)
    if "AIDF_REPORT_EVENTS" in os.environ:
        cfg.report_events = os.environ["AIDF_REPORT_EVENTS"].lower() not in {"0", "false", "no"}
    if "AIDF_COLLECT_INTERVAL" in os.environ:
        cfg.collect_interval_s = float(os.environ["AIDF_COLLECT_INTERVAL"])
    cfg.server_url = os.environ.get("STML_SERVER_URL", cfg.server_url)
    cfg.tenant = os.environ.get("STML_TENANT", cfg.tenant)
    cfg.tokens_file = os.environ.get("STML_TOKENS_FILE", cfg.tokens_file)
    cfg.enrol_token_file = os.environ.get("STML_ENROL_TOKEN_FILE", cfg.enrol_token_file)
    if "AIDF_GUI_PORT" in os.environ:
        cfg.gui_port = int(os.environ["AIDF_GUI_PORT"])
    if cfg.collect_interval_s <= 0:
        raise ValueError("collect_interval_s must be > 0")
    if cfg.queue_capacity <= 0:
        raise ValueError("queue_capacity must be > 0")
    if not 0.0 <= cfg.min_confidence <= 1.0:
        raise ValueError("min_confidence must be within 0..1")
    return cfg


def default_config_path() -> str:
    return os.environ.get("AIDF_CONFIG", "/etc/aidf/agent.toml")


def load_default() -> AgentConfig:
    path = default_config_path()
    if os.path.exists(path):
        return load_agent_config(path)
    return AgentConfig()


if __name__ == "__main__":  # tiny diagnostic: `python -m core.agentconfig`
    cfg = load_default()
    print(f"source={cfg.source} audit_log={cfg.audit_log} data_root={cfg.data_root}",
          file=sys.stderr)
