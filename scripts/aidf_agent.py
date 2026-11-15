#!/usr/bin/env python3
"""AIDefender Linux agent runner.

One process, one config file, one report stream:

* reads ``/etc/aidf/agent.toml`` (or ``--config``);
* builds the configured collector (``linux.auditd`` by default);
* runs the same ingest/rule/gate pipeline as the Windows daemon;
* writes normalized events to ``<data_root>/reports/events.jsonl`` for the
  STML connector and audit records to ``<data_root>/audit/chain.jsonl``.

Usage:
    sudo python3 aidf_agent.py --config /etc/aidf/agent.toml
    python3 aidf_agent.py --config ./agent.toml --once
"""

from __future__ import annotations

import argparse
import os
import platform
import signal
import socket
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent if (HERE.parent / "core").exists() else HERE
sys.path.insert(0, str(ROOT))

from core.agentconfig import load_agent_config  # noqa: E402
from core.auditsource import LinuxAuditSource  # noqa: E402
from core.daemon import Daemon, DaemonConfig, build_default_collectors  # noqa: E402
from core.localgui import LocalGui  # noqa: E402
from core.normalize import HostContext  # noqa: E402


def _host(config) -> HostContext:
    return HostContext(
        host_id=config.host_id or socket.gethostname() or "linux-host",
        os="linux" if sys.platform.startswith("linux") else os.name,
        version=platform.release() or "unknown",
        arch=platform.machine() or "unknown",
        kernel=platform.release() or None,
    )


def _collectors(config):
    if config.source == "linux.auditd":
        # One poll reads whole contiguous audit messages; flush at the end of the
        # poll so --once and the first systemd cycle are not delayed.
        return [LinuxAuditSource(path=config.audit_log, flush_after_s=0.0)]
    return build_default_collectors(DaemonConfig(sources=[config.source],
                                                 audit_log_path=config.audit_log))


def build_daemon(config) -> Daemon:
    os.makedirs(config.data_root, exist_ok=True)
    daemon_config = config.to_daemon_config()
    return Daemon(
        config.data_root,
        config=daemon_config,
        rules_path=config.rules_path or None,
        host=_host(config),
        collectors=_collectors(config),
        collect_interval_s=0.0,  # runner owns the loop
    )


def _touch_report(config) -> None:
    """File-only connectors use the report mtime as an agent liveness signal."""
    path = Path(config.data_root) / "reports" / "events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8"):
        pass
    try:
        os.utime(path, None)
    except OSError:
        pass


def run(config, once: bool = False, duration: float = 0.0) -> int:
    daemon = build_daemon(config)
    stop = threading.Event()

    def _signal(_signum, _frame):
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal)
        except (ValueError, OSError):
            pass

    started = time.monotonic()
    gui = None
    if not once and config.gui_port > 0:
        try:
            gui = LocalGui(daemon, host=config.gui_host, port=config.gui_port,
                           server_url=config.server_url,
                           tokens_file=config.tokens_file)
            host, port = gui.start()
            print(f"aidf-agent: panel http://{host}:{port}/ui/", file=sys.stderr, flush=True)
        except OSError as exc:
            print(f"aidf-agent: panel disabled: {exc}", file=sys.stderr, flush=True)
            gui = None
    print(f"aidf-agent: source={config.source} audit={config.audit_log} "
          f"data={config.data_root}", file=sys.stderr, flush=True)
    try:
        while not stop.is_set():
            collected = daemon.collect_once()
            result = daemon.tick()
            _touch_report(config)
            if once:
                print(f"aidf-agent: collected={collected} {result}", file=sys.stderr, flush=True)
                return 0
            if duration > 0 and time.monotonic() - started >= duration:
                break
            stop.wait(config.collect_interval_s)
    finally:
        if gui is not None:
            gui.stop()
        daemon.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aidf-agent")
    parser.add_argument("--config", default=os.environ.get("AIDF_CONFIG", "/etc/aidf/agent.toml"))
    parser.add_argument("--once", action="store_true", help="one collect/tick cycle")
    parser.add_argument("--duration", type=float, default=0.0, help="0 = until SIGTERM")
    args = parser.parse_args(argv)
    try:
        config = load_agent_config(args.config) if os.path.exists(args.config) else load_agent_config()
    except (OSError, ValueError) as exc:
        print(f"aidf-agent: bad config: {exc}", file=sys.stderr)
        return 2
    try:
        return run(config, once=args.once, duration=args.duration)
    except Exception as exc:  # noqa: BLE001 - systemd must see a non-zero exit
        print(f"aidf-agent: fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
