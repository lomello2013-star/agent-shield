"""Connector -> STML server client (enrolment, signed heartbeat/inventory)."""

from __future__ import annotations

import http.client
import json
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stml.connector.signing import sign


class ServerError(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


def is_replay_conflict(status: int, body: str) -> bool:
    """True for "already accepted" conflicts: the retry re-sent a known nonce.

    The server rejects a repeated nonce with 409 (anti-replay). That means the first
    attempt *was* processed, so a retry must be treated as an acknowledged delivery,
    not as an error — otherwise the connector keeps a sticky last_error forever.
    """
    return status == 409 and "replayed nonce" in body.lower()


class ServerClient:
    def __init__(self, base_url: str, private_key: Ed25519PrivateKey,
                 agent_id: str = "", timeout_s: float = 5.0,
                 ssl_context: object | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.private_key = private_key
        self.agent_id = agent_id
        self.timeout_s = timeout_s
        self.ssl_context = ssl_context
        parts = urlsplit(self.base_url)
        self._https = parts.scheme == "https"
        self._host = parts.hostname or "127.0.0.1"
        self._port = parts.port or (443 if self._https else 80)
        self._prefix = parts.path.rstrip("/")
        self._conn: http.client.HTTPConnection | None = None
        self._lock = threading.Lock()

    def _connect(self) -> http.client.HTTPConnection:
        if self._conn is not None:
            return self._conn
        if self._https:
            context = self.ssl_context or ssl.create_default_context()
            self._conn = http.client.HTTPSConnection(
                self._host, self._port, timeout=self.timeout_s, context=context)
        else:
            self._conn = http.client.HTTPConnection(
                self._host, self._port, timeout=self.timeout_s)
        return self._conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except OSError:
                    pass
                self._conn = None

    def _post(self, path: str, payload: dict[str, Any], signed: bool = False) -> dict[str, Any]:
        raw = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json",
                   "X-Trace-ID": uuid.uuid4().hex}
        if signed:
            headers["X-STML-Signature"] = sign(self.private_key, raw)
        last_error: Exception | None = None
        with self._lock:
            for attempt in range(3):
                try:
                    conn = self._connect()
                    conn.request("POST", self._prefix + path, body=raw, headers=headers)
                    resp = conn.getresponse()
                    data = resp.read()
                    body = data.decode(errors="replace")
                    if is_replay_conflict(resp.status, body):
                        # the earlier attempt was accepted; this is an idempotent ack
                        return {"ok": True, "replayed": True}
                    if resp.status >= 400:
                        raise ServerError(resp.status, body)
                    if resp.will_close:
                        conn.close()
                        self._conn = None
                    return json.loads(data.decode())
                except ServerError:
                    raise
                except (OSError, http.client.HTTPException) as exc:
                    # WSAENOBUFS (10055) can appear after long uptime or socket
                    # pressure; dropping the pooled connection and retrying is safe.
                    last_error = exc
                    if self._conn is not None:
                        try:
                            self._conn.close()
                        except OSError:
                            pass
                        self._conn = None
                    if attempt < 2:
                        time.sleep(0.15 * (attempt + 1))
                        continue
        assert last_error is not None
        raise last_error

    def enrol(self, tenant_id: str, enrolment_token: str, hostname: str, os_name: str,
              arch: str, agent_version: str, connector_version: str,
              pubkey_pem: str) -> str:
        body = self._post("/v0/enrol", {
            "tenant_id": tenant_id,
            "enrolment_token": enrolment_token,
            "hostname": hostname,
            "os": os_name,
            "arch": arch,
            "agent_version": agent_version,
            "connector_version": connector_version,
            "pubkey": pubkey_pem,
        })
        self.agent_id = body["agent_id"]
        return self.agent_id

    def heartbeat(self, heartbeat: Any) -> dict[str, Any]:
        return self._post("/v0/heartbeat", heartbeat.model_dump(mode="json"), signed=True)

    def inventory(self, inventory: Any) -> dict[str, Any]:
        return self._post("/v0/inventory", inventory.model_dump(mode="json"), signed=True)

    def ack_command(self, command_id: str, status: str = "acked",
                    result: dict[str, Any] | None = None) -> dict[str, Any]:
        body = {"agent_id": self.agent_id, "command_id": command_id,
                "status": status, "result": result or {},
                "nonce": uuid.uuid4().hex,
                "sent_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        return self._post("/v0/commands/ack", body, signed=True)
