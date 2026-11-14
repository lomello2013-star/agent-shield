"""Local JSON-RPC endpoint for the connector (`127.0.0.1`, dynamic port).

The connector's internal contract is line-delimited JSON-RPC 2.0. A lock file
records PID + executable hash + port so an operator can discover a live
connector and a stale lock is never trusted silently.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import socketserver
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from stml.connector.security import restrict

MAX_LINE = 1 << 20  # 1 MiB


class AlreadyRunning(RuntimeError):
    pass


def _exe_hash() -> str:
    try:
        raw = Path(sys.executable).read_bytes()
    except OSError:
        return "unknown"
    return hashlib.sha256(raw).hexdigest()[:16]


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server: "ConnectorRpcServer" = self.server.connector  # type: ignore[attr-defined]
        while True:
            line = self.rfile.readline(MAX_LINE + 1)
            if not line:
                return
            if len(line) > MAX_LINE:
                self._send({"jsonrpc": "2.0", "id": None,
                            "error": {"code": "too_large", "message": "line > 1 MiB"}})
                return
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                self._send({"jsonrpc": "2.0", "id": None,
                            "error": {"code": "parse_error", "message": "invalid json"}})
                continue
            self._send(server.dispatch(req))

    def _send(self, payload: dict) -> None:
        self.wfile.write(json.dumps(payload).encode("utf-8") + b"\n")
        self.wfile.flush()


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ConnectorRpcServer:
    def __init__(
        self,
        methods: dict[str, Callable[[dict], Any]],
        host: str = "127.0.0.1",
        port: int = 0,
        lock_path: str | Path | None = None,
        auth_token: str | None = None,
    ) -> None:
        self.methods = methods
        self.host = host
        self.port = port
        self.lock_path = Path(lock_path) if lock_path else None
        self.auth_token = auth_token
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> tuple[str, int]:
        self._check_lock()
        self._server = _Server((self.host, self.port), _Handler)
        self._server.connector = self  # type: ignore[attr-defined]
        self.host, self.port = self._server.server_address
        if self.lock_path:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            self.lock_path.write_text(
                json.dumps({"pid": os.getpid(), "port": self.port,
                            "exe_hash": _exe_hash(), "token": self.auth_token}),
                encoding="utf-8",
            )
            restrict(self.lock_path)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.host, self.port

    def _check_lock(self) -> None:
        if not self.lock_path or not self.lock_path.exists():
            return
        try:
            data = json.loads(self.lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.lock_path.unlink(missing_ok=True)
            return
        pid = int(data.get("pid", 0))
        if pid and _pid_alive(pid) and data.get("exe_hash") == _exe_hash():
            raise AlreadyRunning(f"connector already running (pid={pid}, port={data.get('port')})")
        self.lock_path.unlink(missing_ok=True)

    def dispatch(self, req: dict) -> dict:
        req_id = req.get("id")
        if req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": "invalid_request", "message": "jsonrpc/method required"}}
        if self.auth_token is not None:
            supplied = req.get("token") or (req.get("params") or {}).get("token")
            if supplied != self.auth_token:
                return {"jsonrpc": "2.0", "id": req_id,
                        "error": {"code": "unauthorized", "message": "token required"}}
        method = self.methods.get(req["method"])
        if method is None:
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": "method_not_found", "message": req["method"]}}
        try:
            result = method(req.get("params") or {})
        except Exception as exc:  # noqa: BLE001 - reported to caller, not fatal
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": "internal_error", "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self.lock_path:
            self.lock_path.unlink(missing_ok=True)

    def call(self, method: str, params: dict | None = None, timeout: float = 2.0,
             token: str | None = None) -> dict:
        with socket.create_connection((self.host, self.port), timeout=timeout) as sock:
            sock.sendall(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                                     "token": token or self.auth_token,
                                     "params": params or {}}).encode() + b"\n")
            data = b""
            while not data.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        return json.loads(data)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True
