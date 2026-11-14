"""Signed policy documents (S1 layer B)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class Policy(BaseModel):
    policy_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    channel: Literal["stable", "canary", "beta", "pinned"] = "stable"
    content: dict[str, Any] = Field(default_factory=dict)
    key_id: str = ""
    signature: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def canonical_policy(policy_id: str, version: str, channel: str,
                     content: dict[str, Any]) -> bytes:
    return json.dumps({"policy_id": policy_id, "version": version,
                       "channel": channel, "content": content},
                      sort_keys=True, separators=(",", ":")).encode()
