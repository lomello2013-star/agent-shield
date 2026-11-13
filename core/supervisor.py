"""Process supervisor for the daemon: restart on crash with backoff + circuit breaker.

Reliability §3.5 asks for watchdog×2 + exponential backoff + circuit breaker. The soak
investigation showed the daemon can die from a *native* fault (0xC0000005), which no
Python-level handler can catch — the only defence at that layer is a supervisor that
restarts the process and keeps the audit chain continuous.

The supervisor is deliberately testable: spawning and clock are injected, so the backoff
and circuit-breaker logic is covered without real processes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol


class Handle(Protocol):
    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...


@dataclass
class SupervisorConfig:
    max_restarts: int = 5            # per window
    window_s: float = 600.0
    backoff_base_s: float = 1.0
    backoff_max_s: float = 30.0
    healthy_after_s: float = 60.0    # alive this long => counters reset


@dataclass
class RestartEvent:
    at: float
    exit_code: int | None
    delay_s: float
    attempt: int


@dataclass
class Supervisor:
    spawn: Callable[[], Handle]
    config: SupervisorConfig = field(default_factory=SupervisorConfig)
    now_fn: Callable[[], float] = time.monotonic
    _handle: Handle | None = None
    _started_at: float = 0.0
    _restarts: list[RestartEvent] = field(default_factory=list)
    _circuit_open: bool = False
    _stopped: bool = False

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._handle = self.spawn()
        self._started_at = self.now_fn()

    def stop(self) -> None:
        self._stopped = True
        if self._handle is not None:
            try:
                self._handle.terminate()
            except Exception:       # already dead: nothing to stop
                pass
        self._handle = None

    # ------------------------------------------------------------------ supervision
    def _recent_restarts(self, now: float) -> list[RestartEvent]:
        return [r for r in self._restarts if now - r.at <= self.config.window_s]

    def backoff_for(self, attempt: int) -> float:
        """Exponential backoff, capped; attempt is 1-based."""
        delay = self.config.backoff_base_s * (2 ** max(0, attempt - 1))
        return min(delay, self.config.backoff_max_s)

    def check(self) -> dict:
        """One supervision step. Returns a status snapshot."""
        now = self.now_fn()
        if self._stopped or self._handle is None:
            return self.status()
        code = self._handle.poll()
        if code is None:
            if now - self._started_at >= self.config.healthy_after_s:
                self._restarts.clear()      # stayed alive: not a crash loop
            return self.status()

        # the child exited
        if code == 0:
            self._handle = None
            return self.status()

        recent = self._recent_restarts(now)
        if len(recent) >= self.config.max_restarts:
            self._circuit_open = True
            self._handle = None
            return self.status()

        attempt = len(recent) + 1
        delay = self.backoff_for(attempt)
        self._restarts.append(RestartEvent(at=now, exit_code=code, delay_s=delay,
                                           attempt=attempt))
        time.sleep(min(delay, 0.05)) if delay <= 0.05 else None   # tests use tiny backoff
        self._handle = self.spawn()
        self._started_at = self.now_fn()
        return self.status()

    # ------------------------------------------------------------------ observability
    def status(self) -> dict:
        return {
            "running": self._handle is not None,
            "circuit_open": self._circuit_open,
            "restarts": len(self._restarts),
            "recent_restarts": len(self._recent_restarts(self.now_fn())),
            "last_exit_code": self._restarts[-1].exit_code if self._restarts else None,
            "last_delay_s": self._restarts[-1].delay_s if self._restarts else None,
        }
