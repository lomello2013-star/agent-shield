"""Policy gate: Verdict -> Action proposals, alert budget, suppression (E12/PPV).

Two things are deliberately separated:
  * **containment** (reversible actions) вЂ” may proceed on a confident verdict;
  * **alerting** вЂ” capped by the operational budget (<=1 medium+ alert per host
    per 1-2 weeks), because at realistic prevalence an unbudgeted detector
    produces ~4% PPV and users disable the product.

Irreversible actions never appear here: the gate only proposes action *types*
that `core.response` is allowed to execute (suspend/quarantine/notify).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable

from schemas.v3 import Verdict

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

DEFAULT_ACTIONS: dict[str, tuple[str, ...]] = {
    "critical": ("quarantine", "suspend"),
    "high": ("suspend",),
    "medium": (),
    "low": (),
    "info": (),
}


def ppv(tpr: float, fpr: float, prevalence: float) -> float:
    """Positive predictive value at a given base rate (roadmap В§1.2, E9)."""
    if not 0.0 <= tpr <= 1.0 or not 0.0 <= fpr <= 1.0:
        raise ValueError("tpr/fpr must be within 0..1")
    if not 0.0 <= prevalence <= 1.0:
        raise ValueError("prevalence must be within 0..1")
    tp = tpr * prevalence
    fp = fpr * (1.0 - prevalence)
    return 0.0 if tp + fp == 0 else tp / (tp + fp)


@dataclass
class GateDecision:
    actions: tuple[str, ...]
    alert: bool
    reason: str
    budget_remaining: int
    suppressed: bool = False


@dataclass
class AlertBudget:
    """Rolling per-host alert budget."""

    per_window: int = 1
    window_s: float = 14 * 24 * 3600
    now_fn: Callable[[], float] = time.monotonic
    _alerts: dict[str, deque] = field(default_factory=lambda: defaultdict(deque), repr=False)

    def _trim(self, host: str) -> None:
        q = self._alerts[host]
        cutoff = self.now_fn() - self.window_s
        while q and q[0] < cutoff:
            q.popleft()

    def remaining(self, host: str) -> int:
        self._trim(host)
        return max(0, self.per_window - len(self._alerts[host]))

    def take(self, host: str) -> bool:
        if self.remaining(host) <= 0:
            return False
        self._alerts[host].append(self.now_fn())
        return True

    def used(self, host: str) -> int:
        self._trim(host)
        return len(self._alerts[host])


@dataclass
class SuppressionList:
    """Operator-approved suppressions: (rule_id, target) -> expiry."""

    ttl_s: float = 7 * 24 * 3600
    now_fn: Callable[[], float] = time.monotonic
    _items: dict[tuple[str, str], float] = field(default_factory=dict, repr=False)

    def add(self, rule_id: str, target: str) -> None:
        self._items[(rule_id, target)] = self.now_fn() + self.ttl_s

    def is_suppressed(self, rule_id: str, target: str) -> bool:
        expiry = self._items.get((rule_id, target))
        if expiry is None:
            return False
        if expiry <= self.now_fn():
            del self._items[(rule_id, target)]
            return False
        return True

    def count(self) -> int:
        self._purge()
        return len(self._items)

    def _purge(self) -> None:
        now = self.now_fn()
        for key in [k for k, exp in self._items.items() if exp <= now]:
            del self._items[key]


@dataclass
class PolicyGate:
    min_confidence: float = 0.5
    budget: AlertBudget = field(default_factory=AlertBudget)
    suppressions: SuppressionList = field(default_factory=SuppressionList)
    actions_by_severity: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: dict(DEFAULT_ACTIONS))
    killed_rules: set[str] = field(default_factory=set)
    # F12b: the alert budget is a noise cap; critical findings must not be muted by it,
    # otherwise a ransomware run right after one unrelated alert stays silent.
    critical_bypass_budget: bool = True

    def decide(self, verdict: Verdict, host_id: str, target: str = "") -> GateDecision:
        rule_id = verdict.rule_id or verdict.model_id or ""
        if rule_id in self.killed_rules:
            return GateDecision((), False, "kill_switch", self.budget.remaining(host_id))
        if self.suppressions.is_suppressed(rule_id, target):
            return GateDecision((), False, "suppressed", self.budget.remaining(host_id),
                                suppressed=True)
        if verdict.confidence < self.min_confidence:
            return GateDecision((), False, "low_confidence", self.budget.remaining(host_id))
        if verdict.detector != "rule":
            # ML/behaviour models run in shadow: they may alert (budgeted) but must
            # never trigger containment until calibration + FP budget are proven.
            return GateDecision((), False, "shadow_only", self.budget.remaining(host_id))

        actions = tuple(self.actions_by_severity.get(verdict.severity, ()))
        if not actions:
            # Medium/low/info never trigger containment.
            return GateDecision((), False, "observe_only", self.budget.remaining(host_id))
        if verdict.severity == "critical" and self.critical_bypass_budget:
            # Critical findings alert even with the budget spent; containment happens
            # either way, but silence is never acceptable here.
            self.budget.take(host_id)
            return GateDecision(actions, True, "critical_bypass",
                                self.budget.remaining(host_id))
        if self.budget.take(host_id):
            return GateDecision(actions, True, "alert_and_contain",
                                self.budget.remaining(host_id))
        return GateDecision(actions, False, "contain_without_alert",
                            self.budget.remaining(host_id))

    # ---------------- operational helpers ----------------
    def approve_for_suppression(self, verdict: Verdict, target: str) -> None:
        """After an operator approves an action, stop re-alerting for the same pair."""
        self.suppressions.add(verdict.rule_id or verdict.model_id or "", target)

    def stats(self, host_id: str) -> dict[str, object]:
        return {"budget_used": self.budget.used(host_id),
                "budget_remaining": self.budget.remaining(host_id),
                "suppressions": self.suppressions.count(),
                "killed_rules": sorted(self.killed_rules)}

