"""Read-only tailer for the agent's `*.jsonl` fallback files.

Tracks byte offsets in a small JSON state file, handles partial lines and log
rotation (inode change or shrink). Invalid JSON lines are skipped and counted;
reading never modifies the source files.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


class JsonlTailer:
    def __init__(self, state_path: str | Path) -> None:
        self.state_path = Path(state_path)
        self._state: dict[str, dict] = {}
        self.skipped = 0
        if self.state_path.exists():
            try:
                self._state = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._state = {}

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def read(self, path: str | Path) -> list[dict]:
        path = Path(path)
        if not path.exists():
            return []
        st = path.stat()
        entry = self._state.get(str(path), {"offset": 0, "ino": st.st_ino})
        offset = int(entry.get("offset", 0))
        if entry.get("ino") != st.st_ino or st.st_size < offset:
            offset = 0  # rotated or truncated: reread safely (dedup on report_id)
        records: list[dict] = []
        with path.open("rb") as fh:
            fh.seek(offset)
            data = fh.read()
        # only complete lines are consumed; a partial tail stays unread
        last_nl = data.rfind(b"\n")
        if last_nl < 0:
            if offset == 0 and not st.st_size:
                return []
            return []
        complete = data[: last_nl + 1]
        for raw in complete.splitlines():
            if not raw.strip():
                continue
            try:
                records.append(json.loads(raw))
            except json.JSONDecodeError:
                self.skipped += 1
        self._state[str(path)] = {"offset": offset + len(complete), "ino": st.st_ino}
        self._save()
        return records

    def read_all(self, paths: list[str | Path]) -> list[dict]:
        out: list[dict] = []
        for path in paths:
            out.extend(self.read(path))
        return out
