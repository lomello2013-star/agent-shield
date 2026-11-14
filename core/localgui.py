"""Localhost agent panel API.

The panel is intentionally local-only: it binds ``127.0.0.1`` and has no remote
auth surface. It exposes read-only overview data and two operator actions
(confirm a pending action, run a self-test). The agent itself remains the source
of truth; this is a UI adapter, not a second policy engine.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


class LocalGui:
    def __init__(self, daemon: Any, host: str = "127.0.0.1", port: int = 18080,
                 html_path: str | None = None) -> None:
        self.daemon = daemon
        self.host = host
        self.port = int(port)
        self.html_path = Path(html_path or Path(__file__).resolve().parent.parent /
                              "agent" / "gui" / "index.html")
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ data
    def overview(self) -> dict:
        health = self.daemon.health()
        stats = self.daemon.stats()
        pending = self.daemon.pending_confirmations()
        sources = health.get("sources") or {}
        collectors = stats.get("collectors") or []
        source_names = [str(s.get("name", "")) for s in collectors]
        kernel_loaded = any(name in {"linux.auditd", "linux.ebpf"} for name in source_names)
        rules = stats.get("pipeline", {}).get("rule_counts", {}) or {}
        return {
            "host": stats.get("platform", {}),
            "health": health,
            "stats": {
                "collected": stats.get("collected", 0),
                "verdicts": health.get("verdicts", 0),
                "alerts": health.get("alerts", 0),
                "isolated": stats.get("isolated", False),
                "paused": bool(getattr(self.daemon, "paused", False)),
                "sources": sources,
                "collectors": collectors,
            },
            "policy": stats.get("policy", {}),
            "pending": pending,
            "recent_verdicts": [
                v.model_dump(mode="json")
                for v in getattr(self.daemon.pipeline, "verdicts", [])[-20:]
            ],
            "stack": [
                {"name": "Kernel collector", "state": "loaded" if kernel_loaded else "stopped",
                 "detail": ", ".join(source_names) or "no collector"},
                {"name": "Reflex rules", "state": "active" if rules else "idle",
                 "detail": f"{sum(int(v) for v in rules.values())} evaluations"},
                {"name": "ML model", "state": "shadow", "detail": "no model pack loaded"},
                {"name": "Network visibility", "state": "live" if kernel_loaded else "idle",
                 "detail": "collector-only"},
                {"name": "Self protection",
                 "state": "ok" if health.get("audit_chain_ok") and health.get("integrity_ok")
                 else "degraded",
                 "detail": "audit chain + integrity manifest"},
            ],
        }

    # ------------------------------------------------------------------ server
    def start(self) -> tuple[str, int]:
        gui = self

        class Handler(BaseHTTPRequestHandler):
            def _json(self, code: int, payload: dict) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _html(self) -> None:
                try:
                    body = gui.html_path.read_bytes()
                except OSError:
                    self._json(500, {"error": "ui not found"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - stdlib API
                if self.path in ("/", "/ui", "/ui/"):
                    self._html()
                elif self.path == "/api/overview":
                    self._json(200, gui.overview())
                else:
                    self._json(404, {"error": "not found"})

            def do_POST(self):  # noqa: N802 - stdlib API
                length = int(self.headers.get("Content-Length", "0") or 0)
                try:
                    payload = json.loads(self.rfile.read(length) or b"{}")
                except (ValueError, TypeError):
                    self._json(400, {"error": "invalid json"})
                    return
                if self.path == "/api/confirm":
                    cid = str(payload.get("confirmation_id", ""))
                    decision = str(payload.get("decision", ""))
                    if not cid or decision not in {"approved", "rejected"}:
                        self._json(400, {"error": "confirmation_id and approved|rejected required"})
                        return
                    self._json(200, gui.daemon.confirm(cid, decision, "local-ui"))
                    return
                if self.path == "/api/scan":
                    self._json(200, gui.daemon.run_self_test())
                    return
                if self.path == "/api/pause":
                    gui.daemon.paused = not bool(getattr(gui.daemon, "paused", False))
                    self._json(200, {"paused": gui.daemon.paused})
                    return
                self._json(404, {"error": "not found"})

            def log_message(self, *args):  # keep journald clean
                return

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.host, self.port

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
