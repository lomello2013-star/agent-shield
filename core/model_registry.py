"""Model registry with signed packs and a human gate for promotion.

Roles: `champion` (the model whose verdicts are authoritative), `challenger`
(shadow candidate compared against the champion), `retired`.

Rules:
  * every entry's pack must verify against a trusted public key before it is
    registered — an unsigned/broken model never enters the registry;
  * promotion to `champion` requires a human (`operator=True`); an agent can
    register and compare candidates but cannot crown them;
  * exactly one champion at a time; promoting a challenger to champion retires
    the previous one automatically (recorded, not silent).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from core.modelpack import load_public_key, verify_pack

ROLES = ("champion", "challenger", "retired")


class RegistryError(RuntimeError):
    """Registry operation refused (unverified model, missing role, human gate)."""


@dataclass
class ModelEntry:
    model_id: str
    version: str
    role: str
    artifact: str
    pack_path: str
    metrics: dict = field(default_factory=dict)
    added_at: str = ""

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise RegistryError(f"bad role: {self.role}")
        if not self.model_id:
            raise RegistryError("model_id required")
        if not self.added_at:
            self.added_at = datetime.now(timezone.utc).isoformat()


class ModelRegistry:
    def __init__(self, root: str, public_key_hex: str) -> None:
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.path = os.path.join(self.root, "registry.json")
        self.public_key = load_public_key(public_key_hex)
        self.entries: list[ModelEntry] = []
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as fh:
                payload = json.load(fh)
            for item in payload.get("models", []):
                self.entries.append(ModelEntry(**item))

    # ---------------- persistence ----------------
    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"models": [asdict(e) for e in self.entries]}, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    # ---------------- verification ----------------
    def _verified(self, artifact: str, pack_path: str) -> dict:
        if not os.path.exists(pack_path):
            raise RegistryError(f"pack not found: {pack_path}")
        with open(pack_path, encoding="utf-8") as fh:
            pack = json.load(fh)
        result = verify_pack(pack, artifact, self.public_key)
        if not result.ok:
            raise RegistryError(f"pack verification failed: {result.code} {result.detail}")
        return pack

    # ---------------- operations ----------------
    def register(self, entry: ModelEntry) -> ModelEntry:
        self._verified(entry.artifact, entry.pack_path)
        for existing in self.entries:
            if existing.model_id == entry.model_id and existing.version == entry.version:
                raise RegistryError(f"already registered: {entry.model_id}@{entry.version}")
        if entry.role == "champion" and any(e.role == "champion" for e in self.entries):
            raise RegistryError("champion already exists; use promote() with a human")
        self.entries.append(entry)
        self.save()
        return entry

    def promote(self, model_id: str, version: str, role: str, operator: bool) -> ModelEntry:
        if role not in ("champion", "challenger", "retired"):
            raise RegistryError(f"bad role: {role}")
        if role == "champion" and not operator:
            raise RegistryError("promotion to champion requires a human (operator=True)")
        target = self._find(model_id, version)
        if role == "champion":
            for other in self.entries:
                if other.role == "champion" and other is not target:
                    other.role = "retired"
        target.role = role
        self.save()
        return target

    def retire(self, model_id: str, version: str, operator: bool) -> ModelEntry:
        if not operator:
            raise RegistryError("retirement requires a human")
        target = self._find(model_id, version)
        target.role = "retired"
        self.save()
        return target

    def _find(self, model_id: str, version: str) -> ModelEntry:
        for entry in self.entries:
            if entry.model_id == model_id and entry.version == version:
                return entry
        raise RegistryError(f"not registered: {model_id}@{version}")

    def active(self, role: str | None = None) -> list[ModelEntry]:
        return [e for e in self.entries if role is None or e.role == role]

    def champion(self) -> ModelEntry | None:
        found = self.active("champion")
        return found[0] if found else None
