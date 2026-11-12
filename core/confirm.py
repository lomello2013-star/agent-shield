"""Confirmation gate with fail-safe timeout (R9, §1.2 «необратимое без оператора»).

Rules:
  * reversible actions may run on policy + confidence;
  * destructive actions require an operator; without an operator they are
    **queued** (status pending), never executed;
  * any confirmation that times out is decided by ``FAIL_SAFE_ON_TIMEOUT``
    (immutable: "reject") — timeouts never approve.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from .policy import FAIL_SAFE_ON_TIMEOUT

DESTRUCTIVE_ACTIONS = frozenset({"terminate", "delete", "remove", "wipe"})


@dataclass
class Confirmation:
    action_id: str
    level: str
    timeout_s: float
    created_at: float
    destructive: bool = False
    queued: bool = False
    decision: str = "pending"     # pending | approved | rejected | timeout
    decided_by: str | None = None
    confirmation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class ConfirmationManager:
    """Tracks confirmations and enforces fail-safe semantics."""

    def __init__(self, default_timeout_s: float = 30.0, operator_present: bool = True,
                 now_fn: Callable[[], float] = time.monotonic) -> None:
        self.default_timeout_s = float(default_timeout_s)
        self.operator_present = bool(operator_present)
        self.now_fn = now_fn
        self._items: dict[str, Confirmation] = {}

    # ---------------- requests ----------------
    def request(self, action_id: str, level: str = "normal", destructive: bool = False,
                timeout_s: float | None = None) -> Confirmation:
        if level not in ("critical_system", "protected_dir", "normal"):
            raise ValueError(f"bad confirmation level: {level}")
        conf = Confirmation(
            action_id=action_id,
            level=level,
            timeout_s=float(timeout_s if timeout_s is not None else self.default_timeout_s),
            created_at=self.now_fn(),
            destructive=destructive,
        )
        if destructive and not self.operator_present:
            conf.queued = True          # T3 без оператора — очередь, не исполняем
        self._items[conf.confirmation_id] = conf
        return conf

    # ---------------- resolution ----------------
    def resolve(self, confirmation_id: str, decision: str, decided_by: str = "operator") -> Confirmation:
        if decision not in ("approved", "rejected"):
            raise ValueError("decision must be approved|rejected")
        conf = self._get(confirmation_id)
        if conf.decision != "pending":
            return conf                 # first decision wins; no double-execution
        if conf.queued:
            self._queue_decision(conf, decision, decided_by)
            return conf
        conf.decision = decision
        conf.decided_by = decided_by
        return conf

    def _queue_decision(self, conf: Confirmation, decision: str, decided_by: str) -> None:
        if decision == "approved" and self.operator_present:
            conf.queued = False
            conf.decision = "approved"
            conf.decided_by = decided_by

    # ---------------- timeout / expiry ----------------
    def expire(self) -> list[Confirmation]:
        """Reject timed-out confirmations; keep queued destructive items pending."""
        expired: list[Confirmation] = []
        now = self.now_fn()
        for conf in self._items.values():
            if conf.decision != "pending" or conf.queued:
                continue
            if now - conf.created_at >= conf.timeout_s:
                conf.decision = str(FAIL_SAFE_ON_TIMEOUT)   # "reject"
                conf.decided_by = "timeout"
                expired.append(conf)
        return expired

    # ---------------- execution gate ----------------
    def executable(self, confirmation_id: str) -> bool:
        conf = self._get(confirmation_id)
        return conf.decision == "approved" and not conf.queued

    def pending(self) -> list[Confirmation]:
        return [c for c in self._items.values() if c.decision == "pending"]

    def _get(self, confirmation_id: str) -> Confirmation:
        key = str(confirmation_id)
        try:
            return self._items[key]
        except KeyError as exc:
            raise KeyError(f"unknown confirmation: {confirmation_id}") from exc
