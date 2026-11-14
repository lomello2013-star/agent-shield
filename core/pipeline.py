"""End-to-end pipeline: raw source record в†’ Event v3.0 в†’ priority ingest в†’ rules в†’ Verdict.

This is the user-mode spine used by every detector stage. Ordering matters:
normalization failures are quarantined (and counted), ingest is overflow-free,
rules only ever *produce verdicts* вЂ” execution decisions belong to the policy layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from core.ingest import P0_PROCESS, P1_FILE, P2_NOISE, IngestPipeline
from core.normalize import Normalizer, NormalizationError
from core.rules import RuleEngine
from schemas.v3 import Event, Verdict

# reliability.md В§3 Рї.3: process/credentials > files > auth-noise.
PRIORITY_BY_CATEGORY: dict[str, int] = {
    "process.start": P0_PROCESS,
    "process.exit": P0_PROCESS,
    "process.access": P0_PROCESS,
    "priv.grant": P0_PROCESS,
    "memory.access": P0_PROCESS,
    "defender.tamper": P0_PROCESS,
    "log.tamper": P0_PROCESS,
    "module.load": P0_PROCESS,
    "persistence.change": P1_FILE,
    "registry.change": P1_FILE,
    "file.create": P1_FILE,
    "file.write": P1_FILE,
    "file.exec": P1_FILE,
    "file.delete": P1_FILE,
    "file.read": P1_FILE,
    "script.execute": P1_FILE,
    "net.connect": P1_FILE,
    "net.listen": P1_FILE,
    "dns.query": P1_FILE,
    "auth.success": P2_NOISE,
    "auth.failure": P2_NOISE,
    "config.change": P2_NOISE,
}


def priority_for(category: str) -> int:
    return PRIORITY_BY_CATEGORY.get(category, P2_NOISE)


@dataclass
class Pipeline:
    normalizer: Normalizer
    ingest: IngestPipeline
    engine: RuleEngine
    on_verdict: Callable[[Verdict], None] | None = None
    on_event: Callable[[Event], None] | None = None
    verdicts: list[Verdict] = field(default_factory=list)
    rejected: int = 0

    def submit_raw(self, source: str, raw: dict[str, Any]) -> bool:
        """Normalize and enqueue one raw record. False = quarantined/rejected."""
        event = self.normalizer.normalize_or_quarantine(source, raw)
        if event is None:
            self.rejected += 1
            return False
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception:
                # Reporting is observability, never a detector blocker.
                pass
        key = ""
        if event.actor is not None:
            key = event.actor.sha256 or event.actor.path
        elif event.object is not None:
            key = event.object.path
        return self.ingest.submit(
            category=event.category,
            key=key,
            payload=event.model_dump(mode="json"),
            priority=priority_for(event.category),
            event=event,
        )

    def run_once(self, max_events: int = 500) -> list[Verdict]:
        """Drain the ingest queue and evaluate rules; returns new verdicts."""
        produced: list[Verdict] = []
        for record in self.ingest.drain(max_events):
            # Live records carry the validated Event; spills are replayed as dicts.
            event = record.event if record.event is not None else Event.model_validate(record.payload)
            # An aggregated noise record represents N identical events; rules run
            # once on the representative event (documented approximation).
            for verdict in self.engine.evaluate(event):
                updates = {"event_ts": event.ts_event}
                if verdict.actor_pid is None and event.actor is not None:
                    updates["actor_pid"] = event.actor.pid
                if verdict.object_path is None and event.object is not None:
                    updates["object_path"] = event.object.path
                if updates:
                    verdict = verdict.model_copy(update=updates)
                produced.append(verdict)
                self.verdicts.append(verdict)
                if self.on_verdict is not None:
                    self.on_verdict(verdict)
        return produced

    def stats(self) -> dict[str, Any]:
        return {"ingest": self.ingest.stats(),
                "normalizer": self.normalizer.stats(),
                "rejected": self.rejected,
                "verdicts": len(self.verdicts),
                "rule_counts": self.engine.counts()}

