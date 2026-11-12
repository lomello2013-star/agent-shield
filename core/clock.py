"""Monotonic clock and wall-clock jump detection (reliability.md §3, п.9)."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ClockJump:
    """Detected discontinuity between wall clock and monotonic clock."""

    wall_delta_s: float
    mono_delta_s: float
    skew_s: float


class MonotonicClock:
    """Clock that never goes backwards and detects wall-clock jumps.

    R9-adjacent requirement: correlation and privilege re-checks rely on
    monotonic time, so a wall-clock jump must be detected and reported rather
    than silently used.
    """

    def __init__(
        self,
        jump_threshold_s: float = 5.0,
        mono_fn=time.monotonic,
        wall_fn=time.time,
    ) -> None:
        self._mono_fn = mono_fn
        self._wall_fn = wall_fn
        self.jump_threshold_s = float(jump_threshold_s)
        self._last_mono = mono_fn()
        self._last_wall = wall_fn()
        self.jumps: list[ClockJump] = []

    def mono(self) -> float:
        """Monotonic seconds (not affected by wall-clock changes)."""
        return float(self._mono_fn())

    def mono_ns(self) -> int:
        return int(self.mono() * 1_000_000_000)

    def wall(self) -> float:
        return float(self._wall_fn())

    def detect_jump(self) -> ClockJump | None:
        """Compare wall vs monotonic delta; record and return a jump if any.

        A jump is reported when the wall clock advanced by more than
        ``jump_threshold_s`` relative to monotonic time. Forward jumps are the
        dangerous case for audit correlation; backward jumps are also reported.
        """
        mono_now, wall_now = self.mono(), self.wall()
        mono_delta = mono_now - self._last_mono
        wall_delta = wall_now - self._last_wall
        skew = wall_delta - mono_delta
        self._last_mono, self._last_wall = mono_now, wall_now
        if abs(skew) >= self.jump_threshold_s:
            jump = ClockJump(wall_delta_s=wall_delta, mono_delta_s=mono_delta, skew_s=skew)
            self.jumps.append(jump)
            return jump
        return None
