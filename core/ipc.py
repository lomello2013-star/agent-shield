"""JSON-RPC 2.0 IPC (ADR D10): named pipe on Windows, AF_UNIX on Linux.

Security properties:
  * transport is authenticated with a shared key (``multiprocessing.connection``
    authkey) — an unauthenticated local process cannot even connect;
  * on top of that, every connection must send ``hello`` with a role token;
    methods are authorised per role (viewer < operator < admin), so a read-only
    client cannot quarantine or kill-switch anything;
  * request size is capped and malformed requests get a JSON-RPC error instead of
    a crash; one bad client never takes the server down.
"""

from __future__ import annotations

import os
import pickle
import secrets
import socket
import sys
import threading
from dataclasses import dataclass, field
from multiprocessing.connection import Client, Listener
from typing import Any, Callable

from core.policy import verify_immutable

MAX_MESSAGE = 1 << 20          # 1 MiB per request
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
UNAUTHORIZED = -32001
FORBIDDEN = -32002
NOT_FOUND = -32003

VIEWER_METHODS = {"ping", "health", "stats"}
OPERATOR_METHODS = VIEWER_METHODS | {"self_test", "quarantine", "suspend", "resume", "confirm"}
ADMIN_METHODS = OPERATOR_METHODS | {"kill_switch", "shutdown", "reload_config"}

ROLE_METHODS: dict[str, set[str]] = {
    "viewer": VIEWER_METHODS,
    "operator": OPERATOR_METHODS,
    "admin": ADMIN_METHODS,
}


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


@dataclass
class RpcRegistry:
    """Method table with per-role authorisation."""

    handlers: dict[str, tuple[set[str], Callable[[dict], Any]]] = field(default_factory=dict)

    def register(self, name: str, roles: set[str], fn: Callable[[dict], Any]) -> None:
        if not roles:
            raise ValueError("method must be allowed for at least one role")
        self.handlers[name] = (set(roles), fn)

    def methods_for(self, role: str) -> list[str]:
        return sorted(name for name, (roles, _fn) in self.handlers.items() if role in roles)

    def dispatch(self, request: Any, role: str) -> dict:
        """Execute one request; always returns a JSON-RPC response object."""
        req_id = None
        try:
            if not isinstance(request, dict):
                raise RpcError(INVALID_REQUEST, "request must be an object")
            if request.get("jsonrpc") != "2.0":
                raise RpcError(INVALID_REQUEST, "jsonrpc must be '2.0'")
            if "id" not in request:
                raise RpcError(INVALID_REQUEST, "missing id")
            req_id = request["id"]
            method = request.get("method")
            if not isinstance(method, str) or not method:
                raise RpcError(INVALID_REQUEST, "missing method")
            params = request.get("params", {})
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise RpcError(INVALID_PARAMS, "params must be an object")
            entry = self.handlers.get(method)
            if entry is None:
                raise RpcError(METHOD_NOT_FOUND, f"unknown method: {method}")
            allowed, fn = entry
            if role not in allowed:
                raise RpcError(FORBIDDEN, f"role {role!r} may not call {method!r}")
            result = fn(params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except RpcError as exc:
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": exc.code, "message": exc.message, "data": exc.data}}
        except Exception as exc:                       # never leak a traceback to a client
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": INTERNAL_ERROR, "message": f"{type(exc).__name__}: {exc}"}}


def default_address(name: str = "aidf") -> str:
    if sys.platform == "win32":
        return rf"\\.\pipe\{name}"
    return os.path.join(os.path.expanduser("~"), f".{name}.sock")


@dataclass
class RpcServer:
    address: str
    authkey: bytes
    tokens: dict[str, str]                 # token -> role
    registry: RpcRegistry
    max_message: int = MAX_MESSAGE
    idle_timeout_s: float = 60.0
    _listener: Any = None
    _thread: threading.Thread | None = None
    _stop: threading.Event = field(default_factory=threading.Event)
    _clients: list[threading.Thread] = field(default_factory=list)

    def start(self) -> None:
        if sys.platform != "win32" and os.path.exists(self.address):
            try:
                os.unlink(self.address)
            except OSError:
                pass
        self._listener = Listener(self.address, authkey=self.authkey)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn = self._listener.accept()
            except (OSError, EOFError, Exception):
                break
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()
            self._clients = [c for c in self._clients if c.is_alive()] + [t]

    def _send(self, conn, payload: dict) -> None:
        conn.send(payload)

    def _recv_frame(self, conn) -> Any:
        """Read one frame, enforcing the size limit *before* unpickling (P0-5)."""
        raw = conn.recv_bytes(maxlength=self.max_message)
        return pickle.loads(raw)

    def _handle(self, conn) -> None:
        role = None
        try:
            if not conn.poll(5.0):
                return
            try:
                hello = self._recv_frame(conn)
            except EOFError:
                return
            except OSError:
                self._send(conn, {"jsonrpc": "2.0", "id": None,
                                  "error": {"code": INVALID_REQUEST,
                                            "message": "request too large"}})
                return
            except Exception:
                self._send(conn, {"jsonrpc": "2.0", "id": None,
                                  "error": {"code": PARSE_ERROR,
                                            "message": "unreadable frame"}})
                return
            if not isinstance(hello, dict) or hello.get("method") != "hello":
                self._send(conn, {"jsonrpc": "2.0", "id": None,
                                  "error": {"code": UNAUTHORIZED, "message": "hello required"}})
                return
            token = (hello.get("params") or {}).get("token", "")
            role = self.tokens.get(str(token))
            if role is None:
                self._send(conn, {"jsonrpc": "2.0", "id": hello.get("id"),
                                  "error": {"code": UNAUTHORIZED, "message": "bad token"}})
                return
            self._send(conn, {"jsonrpc": "2.0", "id": hello.get("id"),
                              "result": {"role": role, "methods": self.registry.methods_for(role)}})
            while not self._stop.is_set() and conn.poll(self.idle_timeout_s):
                try:
                    request = self._recv_frame(conn)
                except EOFError:
                    break
                except OSError:
                    # The limit is enforced by recv_bytes before unpickling; the
                    # oversized frame leaves this connection unreadable.
                    self._send(conn, {"jsonrpc": "2.0", "id": None,
                                      "error": {"code": INVALID_REQUEST,
                                                "message": "request too large"}})
                    break
                except Exception:
                    self._send(conn, {"jsonrpc": "2.0", "id": None,
                                      "error": {"code": PARSE_ERROR, "message": "unreadable frame"}})
                    continue
                if not isinstance(request, dict):
                    # a well-formed pickle can still carry a non-object frame; that must
                    # be a protocol error, not a crash in dispatch
                    self._send(conn, {"jsonrpc": "2.0", "id": None,
                                      "error": {"code": INVALID_REQUEST,
                                                "message": "request must be a JSON object"}})
                    continue
                self._send(conn, self.registry.dispatch(request, role))
        except (EOFError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class RpcClient:
    """Thin JSON-RPC client that performs the hello/role handshake."""

    def __init__(self, address: str, authkey: bytes, token: str,
                 timeout: float = 5.0) -> None:
        self._conn = Client(address, authkey=authkey)
        self._id = 0
        self._timeout = timeout
        hello = self._call_raw("hello", {"token": token})
        self.role = hello["role"]
        self.methods = hello["methods"]

    def _call_raw(self, method: str, params: dict | None = None) -> Any:
        self._id += 1
        request = {"jsonrpc": "2.0", "id": self._id, "method": method,
                   "params": params or {}}
        self._conn.send(request)
        if not self._conn.poll(self._timeout):
            raise TimeoutError(f"no response to {method!r}")
        response = self._conn.recv()
        if "error" in response:
            raise RpcError(response["error"]["code"], response["error"]["message"],
                           response["error"].get("data"))
        return response["result"]

    def call(self, method: str, params: dict | None = None) -> Any:
        return self._call_raw(method, params)

    def close(self) -> None:
        try:
            self._conn.close()
        except OSError:
            pass


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def build_daemon_registry(daemon, kill_switch_add: Callable[[str], None] | None = None) -> RpcRegistry:
    """Wire daemon operations to authorised RPC methods."""
    registry = RpcRegistry()

    def _health(_params: dict) -> dict:
        return daemon.health()

    def _stats(_params: dict) -> dict:
        return daemon.stats()

    def _ping(_params: dict) -> dict:
        return {"pong": True}

    def _self_test(_params: dict) -> dict:
        report = daemon.run_self_test()
        if not report["ok"]:
            daemon.log.append("self_test_failed", {"failed": report["failed"]})
        return report

    def _quarantine(params: dict) -> dict:
        path = params.get("path")
        if not isinstance(path, str) or not path:
            raise RpcError(INVALID_PARAMS, "path is required")
        if daemon.response_quarantine is None:
            raise RpcError(INTERNAL_ERROR, "quarantine store not configured")
        entry = daemon.response_quarantine.put(path, params.get("reason", "operator"))
        return {"quarantine_id": entry.quarantine_id, "sha256": entry.sha256}

    def _kill_switch(params: dict) -> dict:
        rule_id = params.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            raise RpcError(INVALID_PARAMS, "rule_id is required")
        if kill_switch_add is not None:
            kill_switch_add(rule_id)
        else:
            daemon.gate.killed_rules.add(rule_id)
        daemon.log.append("kill_switch", {"rule_id": rule_id})
        return {"killed": rule_id}

    def _shutdown(_params: dict) -> dict:
        daemon.log.append("shutdown_requested", {})
        threading.Thread(target=daemon.stop, daemon=True).start()
        return {"stopping": True}

    def _immutable(_params: dict) -> dict:
        verify_immutable()
        return {"immutable": "ok"}

    registry.register("ping", {"viewer", "operator", "admin"}, _ping)
    registry.register("health", {"viewer", "operator", "admin"}, _health)
    registry.register("stats", {"viewer", "operator", "admin"}, _stats)
    registry.register("self_test", {"operator", "admin"}, _self_test)
    registry.register("immutable_check", {"operator", "admin"}, _immutable)
    registry.register("quarantine", {"operator", "admin"}, _quarantine)
    registry.register("kill_switch", {"admin"}, _kill_switch)
    registry.register("shutdown", {"admin"}, _shutdown)
    return registry


def free_pipe_name(prefix: str = "aidf-test") -> str:
    """Unique named-pipe address for tests (Windows) or socket path (Linux)."""
    name = f"{prefix}-{secrets.token_hex(6)}"
    return default_address(name)
