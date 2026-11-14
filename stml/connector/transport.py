"""Outbound transports for connector reports."""

from __future__ import annotations

import json
import urllib.request
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stml.connector.signing import sign
from stml.contracts.v0 import Ack, Report


class Transport(Protocol):
    def send(self, reports: list[Report]) -> list[str]: ...


class ConsoleTransport:
    """VS1 console mode: print accepted reports, ack immediately."""

    def __init__(self) -> None:
        self.seen = 0

    def send(self, reports: list[Report]) -> list[str]:
        for report in reports:
            print(json.dumps({"report_id": report.report_id,
                              "priority": report.priority.value,
                              "kind": report.kind}), flush=True)
            self.seen += 1
        return [r.report_id for r in reports]


class MemoryTransport:
    def __init__(self) -> None:
        self.sent: list[Report] = []

    def send(self, reports: list[Report]) -> list[str]:
        self.sent.extend(reports)
        return [r.report_id for r in reports]


class HttpTransport:
    def __init__(self, base_url: str, token: str = "", timeout_s: float = 5.0,
                 private_key: Ed25519PrivateKey | None = None,
                 ssl_context: object | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s
        self.private_key = private_key
        self.ssl_context = ssl_context

    def send(self, reports: list[Report]) -> list[str]:
        body = json.dumps({"reports": [r.model_dump(mode="json") for r in reports]}).encode()
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.private_key is not None:
            headers["X-STML-Signature"] = sign(self.private_key, body)
        req = urllib.request.Request(self.base_url + "/v0/reports", data=body,
                                     headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout_s,
                                    context=self.ssl_context) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return [str(x) for x in Ack.model_validate(data).acked]
