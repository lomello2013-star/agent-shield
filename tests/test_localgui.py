"""Localhost agent panel API: overview, self-test, pause, confirmation."""

from __future__ import annotations

import json
import urllib.request

from core.daemon import Daemon, DaemonConfig
from core.localgui import LocalGui
from core.normalize import HostContext

HOST = HostContext(host_id="h", os="linux", version="6", arch="x64")


def _daemon(tmp_path):
    return Daemon(str(tmp_path / "d"), config=DaemonConfig(sources=["linux.auditd"],
                                                           event_reports=False),
                  host=HOST, collectors=[])


def _post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=5).read())


def test_overview_has_live_state(tmp_path):
    d = _daemon(tmp_path)
    gui = LocalGui(d, port=0)
    host, port = gui.start()
    try:
        data = json.loads(urllib.request.urlopen(f"http://{host}:{port}/api/overview",
                                                 timeout=5).read())
        assert data["health"]["status"] in {"ok", "degraded", "safe"}
        assert any(x["name"] == "Collector" for x in data["stack"])
        assert "pending" in data and "recent_verdicts" in data
        html = urllib.request.urlopen(f"http://{host}:{port}/ui/", timeout=5).read()
        assert b"AIDefender Agent" in html
    finally:
        gui.stop()
        d.stop()


def test_server_console_url_contains_only_local_tokens(tmp_path):
    tokens = tmp_path / "tokens.json"
    tokens.write_text(json.dumps({"viewer_token": "v", "admin_token": "a",
                                  "approver_token": "p"}), encoding="utf-8")
    d = _daemon(tmp_path)
    gui = LocalGui(d, port=0, server_url="http://127.0.0.1:8080",
                   tokens_file=str(tokens))
    host, port = gui.start()
    try:
        data = json.loads(urllib.request.urlopen(
            f"http://{host}:{port}/api/server-console", timeout=5).read())
        assert data["url"].startswith("http://127.0.0.1:8080/ui/#")
        assert "viewer=v" in data["url"] and "admin=a" in data["url"]
    finally:
        gui.stop()
        d.stop()


def test_pause_and_scan(tmp_path):
    d = _daemon(tmp_path)
    gui = LocalGui(d, port=0)
    host, port = gui.start()
    try:
        assert _post(f"http://{host}:{port}/api/pause", {})["paused"] is True
        assert d.paused is True
        assert _post(f"http://{host}:{port}/api/pause", {})["paused"] is False
        assert d.paused is False
        result = _post(f"http://{host}:{port}/api/scan", {})
        assert "ok" in result
    finally:
        gui.stop()
        d.stop()


def test_confirm_endpoint_resolves_pending(tmp_path):
    d = _daemon(tmp_path)
    conf = d.confirmations.request("action-1")
    d.pending_actions[conf.confirmation_id] = {
        "action_id": "a", "type": "notify", "target": "x"}
    gui = LocalGui(d, port=0)
    host, port = gui.start()
    try:
        result = _post(f"http://{host}:{port}/api/confirm",
                       {"confirmation_id": conf.confirmation_id,
                        "decision": "rejected"})
        assert result["status"] == "rejected"
        assert not d.pending_confirmations()
    finally:
        gui.stop()
        d.stop()
