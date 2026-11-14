"""File-backed command queue for the agent control plane (Phase B)."""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any


class CommandQueue:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()

    def _load(self) -> list[dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            commands = data.get("commands", []) if isinstance(data, dict) else []
            return [c for c in commands if isinstance(c, dict)]
        except (OSError, json.JSONDecodeError):
            return []

    def _save(self, commands: list[dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"commands": commands}, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def enqueue(self, kind: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            commands = self._load()
            command = {"command_id": str(uuid.uuid4()), "kind": kind,
                       "payload": payload or {}, "status": "pending",
                       "created_at": datetime.now(timezone.utc).isoformat()}
            commands.append(command)
            self._save(commands)
            return command

    def poll(self) -> list[dict[str, Any]]:
        with self._lock:
            return [c for c in self._load() if c.get("status") == "pending"]

    def ack(self, command_id: str, status: str = "acked",
            result: dict[str, Any] | None = None) -> dict[str, Any] | None:
        with self._lock:
            commands = self._load()
            for command in commands:
                if command.get("command_id") == command_id:
                    command["status"] = status
                    command["acked_at"] = datetime.now(timezone.utc).isoformat()
                    command["result"] = result or {}
                    self._save(commands)
                    return command
            return None
