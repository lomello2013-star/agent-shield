"""Minimal trace propagation (OTel-compatible headers)."""

from __future__ import annotations

import re
import uuid

_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")


def trace_id_from(headers: dict[str, str]) -> str:
    incoming = headers.get("traceparent") or headers.get("x-trace-id") or ""
    match = _TRACEPARENT.match(incoming.strip().lower())
    if match:
        return match.group(1)
    if re.fullmatch(r"[0-9a-f]{32}", incoming.strip().lower()):
        return incoming.strip().lower()
    return uuid.uuid4().hex
