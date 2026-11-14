"""Connector -> STML server client (enrolment, signed heartbeat/inventory)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stml.connector.signing import sign


class ServerError(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body


class ServerClient:
    def __init__(self, base_url: str, private_key: Ed25519PrivateKey,
                 agent_id: str = "", timeout_s: float = 5.0,
                 ssl_context: object | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.private_key = private_key
        self.agent_id = agent_id
        self.timeout_s = timeout_s
        self.ssl_context = ssl_context

    def _post(self, path: str, payload: dict[str, Any], signed: bool = False) -> dict[str, Any]:
        raw = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json",
                   "X-Trace-ID": uuid.uuid4().hex}
        if signed:
            headers["X-STML-Signature"] = sign(self.private_key, raw)
        req = urllib.request.Request(self.base_url + path, data=raw, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s,
                                        context=self.ssl_context) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raise ServerError(exc.code, exc.read().decode(errors="replace")) from exc

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
        self.agent_id = str(body["agent_id"])
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
