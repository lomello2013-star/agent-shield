"""Watchdog with backoff and circuit breaker (R3 MTTR ≤ 30 s, R4).

Two watchdogs are required by the roadmap: the in-process supervisor (this module)
and an external one (SCM on Windows / systemd on Linux). ``ExternalWatchdog``
models the second one as a heartbeat file that the external supervisor touches;
if it goes stale, the system must treat it as an incident rather than "all good".
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Callable


class ProcessHandle:
    """Protocol-like base for a supervised process."""

    def poll(self) -> int | None:  # pragma: no cover - interface
        raise NotImplementedError

    def terminate(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class Supervisor:
    """Restarts a crashed service with exponential backoff and a circuit breaker."""

    spawn: Callable[[], ProcessHandle]
    name: str = "aidfd"
    backoff: tuple[float, ...] = (0.0, 1.0, 2.0, 4.0, 8.0)
    max_failures: int = 5
    failure_window_s: float = 60.0
    max_restart_s: float = 30.0
    now_fn: Callable[[], float] = time.monotonic
    sleep_fn: Callable[[float], None] = time.sleep

    handle: ProcessHandle | None = None
    state: str = "stopped"           # stopped | running | failed
    starts: int = 0
    crashes: int = 0
    failures: list[float] = field(default_factory=list)
    restart_latencies: list[float] = field(default_factory=list)
    _started_at: float = 0.0
    _pending_restart_at: float | None = None

    # ---------------- single supervision cycle ----------------
    def tick(self) -> str:
        """One supervision step: spawn if needed, detect exit, schedule restart."""
        if self.state == "failed":
            return self.state
        if self._pending_restart_at is not None:
            if self.now_fn() >= self._pending_restart_at:
                self._pending_restart_at = None
                return self._spawn()
            return self.state           # backoff still running: do not spawn early
        if self.state == "stopped" or self.handle is None:
            return self._spawn()
        rc = self.handle.poll()
        if rc is None:
            return self.state
        # process exited
        self.handle = None
        self.crashes += 1
        self.state = "stopped"
        now = self.now_fn()
        self.failures = [t for t in self.failures if now - t <= self.failure_window_s]
        self.failures.append(now)
        if len(self.failures) > self.max_failures:
            self.state = "failed"
            return self.state
        delay = self.backoff[min(len(self.failures) - 1, len(self.backoff) - 1)]
        delay = min(delay, self.max_restart_s)
        self.restart_latencies.append(delay)
        self._pending_restart_at = now + delay
        return self.state

    def _spawn(self) -> str:
        if self.state == "failed":
            return self.state
        self.handle = self.spawn()
        self.starts += 1
        self.state = "running"
        return self.state

    def reset(self, operator: bool) -> bool:
        """`failed` persists until a human resets it (не «само вылечивается»)."""
        if self.state != "failed" or not operator:
            return False
        self.failures.clear()
        self.state = "stopped"
        return True

    def run_until(self, deadline_s: float, step_s: float = 0.05) -> dict:
        """Supervise until wall-clock deadline; used by fault-injection tests."""
        end = self.now_fn() + deadline_s
        while self.now_fn() < end:
            self.tick()
            if self.state == "running":
                time.sleep(0)
            self.sleep_fn(step_s)
        return self.stats()

    def stats(self) -> dict[str, object]:
        return {
            "name": self.name,
            "state": self.state,
            "starts": self.starts,
            "crashes": self.crashes,
            "failures_in_window": len(self.failures),
            "restart_latencies": [round(x, 3) for x in self.restart_latencies],
        }


@dataclass
class ExternalWatchdog:
    """Models SCM/systemd: a heartbeat file touched by the external supervisor."""

    heartbeat_path: str
    timeout_s: float = 120.0
    now_fn: Callable[[], float] = time.monotonic

    def touch(self) -> None:
        os.makedirs(os.path.dirname(self.heartbeat_path) or ".", exist_ok=True)
        with open(self.heartbeat_path, "w", encoding="utf-8") as fh:
            fh.write(str(self.now_fn()))
            fh.flush()
            os.fsync(fh.fileno())

    def check(self) -> dict[str, object]:
        if not os.path.exists(self.heartbeat_path):
            return {"healthy": False, "reason": "external watchdog heartbeat missing"}
        try:
            with open(self.heartbeat_path, "r", encoding="utf-8") as fh:
                last = float(fh.read().strip())
        except (OSError, ValueError):
            return {"healthy": False, "reason": "external watchdog heartbeat unreadable"}
        age = self.now_fn() - last
        if age > self.timeout_s:
            return {"healthy": False, "reason": f"external heartbeat stale: {age:.1f}s"}
        return {"healthy": True, "age_s": round(age, 3)}
