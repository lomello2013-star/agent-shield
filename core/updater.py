"""Dual-slot A/B updates, canary gating, rollback and kill-switch (R6, §9).

Guarantees:
  * update is written into the inactive slot, verified by sha256, then the
    pointer is switched atomically (``os.replace``), so a crash mid-update leaves
    the previous slot intact;
  * a health regression triggers rollback to the previous slot;
  * canary rollout is a deterministic hash of (release, host) — 1 % of the fleet
    can be pinned to the new release without a central coordinator.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from typing import Callable


class UpdateError(RuntimeError):
    """Update/rollback failure (never swallowed)."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canary_selected(host_id: str, release_id: str, percent: float) -> bool:
    """Deterministic canary decision: stable for the same host+release pair."""
    if not 0.0 <= percent <= 100.0:
        raise ValueError("percent must be within 0..100")
    digest = hashlib.sha256(f"{release_id}:{host_id}".encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:4], "big") % 10_000
    return bucket < int(percent * 100)


@dataclass
class DualSlot:
    root: str
    slots: tuple[str, str] = ("A", "B")
    pointer_name: str = "active.json"
    kill_switch_name: str = "killswitch.json"
    _state: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.root = os.path.abspath(self.root)
        os.makedirs(self.root, exist_ok=True)
        for slot in self.slots:
            os.makedirs(self._slot_dir(slot), exist_ok=True)
        # The factory slot must be verifiable, otherwise a first rollback would
        # fail for the wrong reason (nothing to roll back to).
        if not os.path.exists(os.path.join(self._slot_dir(self.slots[0]), "manifest.json")):
            self._write_manifest(self.slots[0], {"version": "0.0.0", "files": {}})

    # ---------------- paths ----------------
    def _slot_dir(self, slot: str) -> str:
        if slot not in self.slots:
            raise ValueError(f"unknown slot: {slot}")
        return os.path.join(self.root, "slots", slot)

    def _pointer_path(self) -> str:
        return os.path.join(self.root, self.pointer_name)

    # ---------------- pointer ----------------
    def pointer(self) -> dict:
        path = self._pointer_path()
        if not os.path.exists(path):
            return {"slot": "A", "version": "0.0.0", "previous": None}
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def active_slot(self) -> str:
        return self.pointer()["slot"]

    def inactive_slot(self) -> str:
        active = self.active_slot()
        return self.slots[1] if active == self.slots[0] else self.slots[0]

    def _write_pointer(self, slot: str, version: str, previous: str | None) -> None:
        path = self._pointer_path()
        tmp = path + ".tmp"
        payload = {"slot": slot, "version": version, "previous": previous}
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)   # atomic switch

    def _write_manifest(self, slot: str, manifest: dict) -> None:
        path = os.path.join(self._slot_dir(slot), "manifest.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    # ---------------- stage / activate / rollback ----------------
    def stage(self, version: str, files: dict[str, bytes]) -> dict:
        """Write payload into the inactive slot and verify hashes."""
        slot = self.inactive_slot()
        target = self._slot_dir(slot)
        shutil.rmtree(target, ignore_errors=True)
        os.makedirs(target, exist_ok=True)
        manifest = {"version": version, "files": {}}
        for rel, data in files.items():
            safe = os.path.normpath(rel)
            if safe.startswith("..") or os.path.isabs(safe):
                raise UpdateError(f"unsafe path in update payload: {rel}")
            dest = os.path.join(target, safe)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            manifest["files"][safe] = sha256_bytes(data)
        self._write_manifest(slot, manifest)
        if not self.verify_slot(slot):
            raise UpdateError("staged payload failed verification")
        return {"slot": slot, "manifest": manifest}

    def verify_slot(self, slot: str) -> bool:
        target = self._slot_dir(slot)
        manifest_path = os.path.join(target, "manifest.json")
        if not os.path.exists(manifest_path):
            return False
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        for rel, expected in manifest.get("files", {}).items():
            path = os.path.join(target, rel)
            if not os.path.exists(path):
                return False
            with open(path, "rb") as fh:
                if sha256_bytes(fh.read()) != expected:
                    return False
        return True

    def activate(self, slot: str, version: str) -> dict:
        """Atomically switch the pointer to a verified slot."""
        if not self.verify_slot(slot):
            raise UpdateError(f"slot {slot} is not verified; refusing to activate")
        previous = self.active_slot()
        self._write_pointer(slot, version, previous)
        return self.pointer()

    def rollback(self) -> dict:
        current = self.pointer()
        previous = current.get("previous")
        if previous is None or previous == current["slot"]:
            raise UpdateError("no previous slot to roll back to")
        if not self.verify_slot(previous):
            raise UpdateError("previous slot failed verification; manual intervention required")
        self._write_pointer(previous, self.pointer().get("version", "unknown"), current["slot"])
        return self.pointer()

    # ---------------- health-gated update ----------------
    def update_with_health_gate(self, version: str, files: dict[str, bytes],
                                health: Callable[[], bool]) -> dict:
        """Stage → activate → health check; rollback automatically on regression."""
        staged = self.stage(version, files)
        before = self.pointer()
        self.activate(staged["slot"], version)
        try:
            ok = bool(health())
        except Exception:
            ok = False
        if ok:
            return {"result": "updated", "slot": staged["slot"], "version": version}
        self.rollback()
        return {"result": "rolled_back", "slot": before["slot"],
                "version": before.get("version"), "regression": True}

    # ---------------- kill switch ----------------
    def _kill_path(self) -> str:
        return os.path.join(self.root, self.kill_switch_name)

    def _kill_state(self) -> dict:
        path = self._kill_path()
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def set_kill_switch(self, item_id: str, enabled: bool) -> dict:
        state = self._kill_state()
        state[item_id] = bool(enabled)
        tmp = self._kill_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._kill_path())
        return state

    def is_killed(self, item_id: str) -> bool:
        return bool(self._kill_state().get(item_id, False))
