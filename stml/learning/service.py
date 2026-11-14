"""Learning pipeline (S4): opt-in telemetry, PII filter, cases, models."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from stml.server.store import Store
from stml.trust.service import TrustService

RAW_KEYS = {
    "path", "file", "filename", "cmdline", "command_line", "raw", "username",
    "user", "hostname", "ip", "remote_ip", "src_ip", "dst_ip", "domain", "url",
}
ID_KEYS = {"sha256", "md5", "hash", "file_hash", "process_hash", "signer"}


def filter_event(event: dict[str, Any], salt: str) -> dict[str, Any]:
    """Drop raw identifiers, hash stable ids; recursion keeps lists/dicts."""
    out: dict[str, Any] = {}
    for key, value in event.items():
        if key in RAW_KEYS:
            continue
        if key in ID_KEYS and isinstance(value, str):
            out[key] = "h:" + hashlib.sha256((salt + value).encode()).hexdigest()[:32]
        elif isinstance(value, dict):
            out[key] = filter_event(value, salt)
        elif isinstance(value, list):
            out[key] = [filter_event(v, salt) if isinstance(v, dict) else v for v in value]
        else:
            out[key] = value
    return out


class LearningService:
    def __init__(self, store: Store, trust: TrustService, salt: str = "stml") -> None:
        self.store = store
        self.trust = trust
        self.salt = salt

    def ingest(self, agent_id: str, events: list[dict[str, Any]], consent: bool) -> int:
        if not consent:
            raise PermissionError("telemetry requires explicit opt-in")
        filtered = [filter_event(e, self.salt) for e in events if isinstance(e, dict)]
        return self.store.add_telemetry(agent_id, filtered)

    def add_case(self, case_id: str, report_id: str, label: str,
                 holdout: bool, features: dict[str, Any]) -> None:
        self.store.add_case(case_id, report_id, label, holdout, features)

    def _model_key(self) -> dict[str, Any]:
        key = self.trust.active("model") or self.trust.create_key("model")
        return key

    def register_model(self, name: str, version: str,
                       metrics: dict[str, Any]) -> dict[str, Any]:
        key = self._model_key()
        canonical = json.dumps({"name": name, "version": version, "metrics": metrics},
                               sort_keys=True, separators=(",", ":")).encode()
        signature = self.trust.sign(key["key_id"], canonical)
        model_id = self.store.add_model(name, version, metrics, signature, key["key_id"])
        return {"model_id": model_id, "key_id": key["key_id"], "signature": signature}

    def regress(self, model_id: int) -> dict[str, Any]:
        model = self.store.model(model_id)
        if model is None:
            raise KeyError("unknown model")
        active = self.store.active_model()
        reasons: list[str] = []
        if active is not None:
            base, new = active["metrics"], model["metrics"]
            if new.get("tpr_at_fpr", 0) < base.get("tpr_at_fpr", 1) - 1e-9:
                reasons.append("tpr regression")
            if new.get("fp_budget", 0) > base.get("fp_budget", 0) + 1e-9:
                reasons.append("fp budget regression")
        ok = not reasons
        self.store.set_model_status(model_id, "regressed" if ok else "rejected")
        return {"model_id": model_id, "ok": ok, "reasons": reasons,
                "baseline": active["metrics"] if active else None}

    def activate(self, model_id: int) -> dict[str, Any]:
        return self.store.activate_model(model_id)

    def rollback(self) -> dict[str, Any]:
        return self.store.rollback_model()
