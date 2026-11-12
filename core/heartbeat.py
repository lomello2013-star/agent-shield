"""Heartbeat + synthetic probe per telemetry source (R2 / reliability.md §3.1).

"Тихая смерть" источника выглядит как «всё хорошо»: ETW-сессия потеряна, auditd
не применил правила, eBPF-программа выгружена. Механизм: heartbeat от каждого
источника + синтетическая проба каждые 60 с; молчание дольше timeout — incident.

R2: детекция тихого отказа 100 % за ≤60 с.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class Incident:
    source: str
    kind: str          # "silent" | "probe_failed"
    silent_for_s: float
    detail: str = ""


@dataclass
class SourceState:
    last_beat_mono: float
    last_probe_mono: float
    seq: int | None = None
    incident_open: bool = False
    healthy: bool = True
    degraded: bool = False


@dataclass
class HeartbeatMonitor:
    """Tracks liveness of telemetry sources.

    Args:
        timeout_s: silence after which a source is considered dead (R2: 60 s).
        warn_s: silence after which the source is reported degraded (early warning).
        escalate_s: silence after which an incident is opened even before timeout_s;
            this gives R2 a margin (worst-case detection <= escalate_s, not timeout_s).
        probe_interval_s: how often the synthetic probe runs.
        now_fn: injectable monotonic clock (tests accelerate time).
        on_incident: callback invoked once per outage.
    """

    timeout_s: float = 60.0
    warn_s: float | None = None
    escalate_s: float | None = None
    probe_interval_s: float = 60.0
    now_fn: Callable[[], float] = time.monotonic
    on_incident: Callable[[Incident], None] | None = None
    _sources: dict[str, SourceState] = field(default_factory=dict)
    _probes: dict[str, Callable[[], bool]] = field(default_factory=dict)
    incidents: list[Incident] = field(default_factory=list)
    warnings: list[Incident] = field(default_factory=list)

    # ---------- registration ----------
    def __post_init__(self) -> None:
        # Derive the early thresholds from the contract when not set explicitly:
        # warn at half the timeout, escalate at three quarters (R2 keeps a 25 % margin).
        if self.warn_s is None:
            self.warn_s = self.timeout_s * 0.5
        if self.escalate_s is None:
            self.escalate_s = self.timeout_s * 0.75
        if not 0 < self.warn_s < self.escalate_s <= self.timeout_s:
            raise ValueError("expected 0 < warn_s < escalate_s <= timeout_s")

    def register(self, source: str, probe: Callable[[], bool] | None = None) -> None:
        if not source:
            raise ValueError("source name must be non-empty")
        now = self.now_fn()
        self._sources[source] = SourceState(last_beat_mono=now, last_probe_mono=now)
        if probe is not None:
            self._probes[source] = probe

    def sources(self) -> list[str]:
        return sorted(self._sources)

    # ---------- liveness ----------
    def beat(self, source: str, seq: int | None = None) -> None:
        """Record a heartbeat. Unknown sources are rejected loudly."""
        state = self._sources.get(source)
        if state is None:
            raise KeyError(f"unregistered source: {source}")
        if seq is not None and state.seq is not None and seq < state.seq:
            # Out-of-order heartbeats do not extend liveness.
            return
        state.last_beat_mono = self.now_fn()
        state.seq = seq if seq is not None else state.seq
        state.healthy = True
        state.degraded = False
        state.incident_open = False

    def probe(self, source: str) -> bool:
        """Run the synthetic probe for a source. A failed probe is an incident."""
        probe = self._probes.get(source)
        if probe is None:
            raise KeyError(f"no probe registered for: {source}")
        state = self._sources[source]
        state.last_probe_mono = self.now_fn()
        try:
            ok = bool(probe())
        except Exception:
            ok = False
        if not ok:
            self._raise_incident(source, "probe_failed",
                                 silent_for_s=self.now_fn() - state.last_beat_mono,
                                 detail="synthetic probe returned false")
        return ok

    # ---------- detection ----------
    def check(self) -> list[Incident]:
        """Detect silent sources.

        Three thresholds, so that R2 keeps a margin under the 60 s contract:
          * ``warn_s``     — source reported degraded (early warning, no incident);
          * ``escalate_s`` — incident opened early, still inside the contract;
          * ``timeout_s``  — hard contract limit (kept for compatibility).
        Returns incidents opened by this call.
        """
        now = self.now_fn()
        opened: list[Incident] = []
        for source, state in self._sources.items():
            silence = now - state.last_beat_mono
            if state.incident_open:
                continue
            if silence > self.escalate_s:
                kind = "silent" if silence > self.timeout_s else "stalled"
                inc = self._raise_incident(source, kind, silence,
                                           detail=f"no heartbeat for {silence:.1f}s")
                opened.append(inc)
            elif silence > self.warn_s and not state.degraded:
                state.degraded = True
                warning = Incident(source=source, kind="degraded",
                                   silent_for_s=round(silence, 3),
                                   detail=f"no heartbeat for {silence:.1f}s")
                self.warnings.append(warning)
        return opened

    def _raise_incident(self, source: str, kind: str, silent_for_s: float, detail: str) -> Incident:
        state = self._sources[source]
        state.healthy = False
        if state.incident_open and kind == "silent":
            return Incident(source, kind, silent_for_s, detail)
        state.incident_open = True
        inc = Incident(source=source, kind=kind, silent_for_s=round(silent_for_s, 3), detail=detail)
        self.incidents.append(inc)
        if self.on_incident is not None:
            self.on_incident(inc)
        return inc

    # ---------- observability ----------
    def health(self) -> dict[str, dict[str, object]]:
        now = self.now_fn()
        out: dict[str, dict[str, object]] = {}
        for source, state in self._sources.items():
            out[source] = {
                "healthy": state.healthy,
                "degraded": state.degraded,
                "silent_for_s": round(now - state.last_beat_mono, 3),
                "incident_open": state.incident_open,
                "seq": state.seq,
            }
        return out

    def all_healthy(self) -> bool:
        return all(s.healthy for s in self._sources.values())
