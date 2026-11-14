"""Map STML learning cases to the agent's v3 CaseMemoryEntry."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from schemas.v3 import CaseMemoryEntry


def case_to_memory_entry(case: dict[str, Any], verdict: dict[str, Any],
                         platform: str, confirmed_by: str = "analyst") -> dict[str, Any]:
    """Convert a STML case row + a full v3 Verdict into CaseMemoryEntry.

    STML cases carry label/features only; the caller must supply a real verdict
    (not a synthetic one) so the entry is attributable.
    """
    created = case.get("created_at")
    if isinstance(created, (int, float)):
        created_at = datetime.fromtimestamp(created, timezone.utc)
    elif isinstance(created, str):
        created_at = datetime.fromisoformat(created.replace("Z", "+00:00"))
    else:
        created_at = datetime.now(timezone.utc)
    features = {str(k): float(v) for k, v in (case.get("features") or {}).items()}
    entry = CaseMemoryEntry.model_validate({
        "case_id": case.get("case_id"),
        "created_at": created_at,
        "confirmed_by": confirmed_by,
        "features": features,
        "verdict": verdict,
        "platform": platform,
        "context": {"label": case.get("label"), "report_id": case.get("report_id")},
    })
    return entry.model_dump(mode="json")
