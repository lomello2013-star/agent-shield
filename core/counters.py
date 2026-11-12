"""Loss counters — the "never silently drop" primitive (reliability.md §3, п.2).

Every loss path in the ingest pipeline must call `LossCounters.inc`. A non-zero
`lost` or `overflow` counter is an incident (R8: <0.01% loss, visible, not silent).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable

# Counter names used across the platform.
LOST = "lost"
OVERFLOW = "overflow"
BACKLOG = "backlog"
SPILLED = "spilled"
EVICTED = "evicted"
AGGREGATED = "aggregated"
REPLAYED = "replayed"


@dataclass
class LossCounters:
    """Thread-safe counters plus an alert callback on any loss."""

    on_loss: Callable[[str, int], None] | None = None
    _counts: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, name: str, n: int = 1) -> int:
        if n < 0:
            raise ValueError("counter delta must be non-negative")
        with self._lock:
            value = self._counts.get(name, 0) + n
            self._counts[name] = value
        if n and name in (LOST, OVERFLOW) and self.on_loss is not None:
            self.on_loss(name, n)
        return value

    def get(self, name: str) -> int:
        with self._lock:
            return self._counts.get(name, 0)

    def set(self, name: str, value: int) -> None:
        with self._lock:
            self._counts[name] = int(value)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def loss_total(self) -> int:
        with self._lock:
            return self._counts.get(LOST, 0) + self._counts.get(OVERFLOW, 0)

    def is_clean(self) -> bool:
        """True when nothing was lost or overflowed."""
        return self.loss_total() == 0
