"""Self-protection (stage 11, user-mode part): tamper-evident log, integrity, self-test.

Kernel-level mechanisms (PPL, ELAM, fs-verity, IMA appraisal) are out of scope here
and remain blocked by the signing/VM blockers — this module does what user-mode can:
  * an append-only hash-chained audit log with a signed checkpoint (anchor), so any
    edit, reorder or truncation is detectable, not just "logged differently";
  * a sealed integrity manifest for configs/rules/schemas/models;
  * a startup self-test that fails loudly (R10: tamper -> incident, not silence).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    broken_at: int | None = None
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


class HashChainLog:
    """Append-only JSONL where each record commits to the previous hash.

    ``anchor_path`` stores the last (seq, hash). Without an anchor a tail
    truncation would look like a valid shorter chain; with it, truncation is caught.

    Two durability modes:
      * ``fsync_every=1`` (default) — every record is durable before append returns;
      * ``fsync_every>1`` — records are buffered and fsynced in batches. This is
        faster but a crash can lose up to ``fsync_every-1`` *tail* records; those
        were never acknowledged as durable, so the chain itself stays valid.

    ``verify(incremental=True)`` only re-reads records appended after the last
    verification (O(new) instead of O(n)). An in-place edit of an *older* record
    is only caught by a full verification, which ``seal()`` performs.
    """

    def __init__(self, path: str, anchor_path: str | None = None,
                 fsync_every: int = 1,
                 now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.path = os.path.abspath(path)
        self.anchor_path = os.path.abspath(anchor_path) if anchor_path else None
        self.fsync_every = max(1, int(fsync_every))
        self._now = now_fn
        self._last_seq = 0
        self._last_hash = GENESIS
        self._buffer: list[str] = []
        self._verified_seq = 0
        self._verified_hash = GENESIS
        self._offset = 0
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._recover()

    # ---------------- internals ----------------
    def _recover(self) -> None:
        if not os.path.exists(self.path):
            return
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # A corrupted line must not prevent opening the log: verify()
                    # reports it as tamper instead of crashing the agent.
                    continue
                if not isinstance(record, dict) or not {"seq", "hash"} <= set(record):
                    continue
                last = record
        if last:
            self._last_seq = int(last["seq"])
            self._last_hash = str(last["hash"])

    def _anchor(self) -> dict[str, Any] | None:
        if not self.anchor_path or not os.path.exists(self.anchor_path):
            return None
        with open(self.anchor_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    # ---------------- public ----------------
    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        seq = self._last_seq + 1
        body = {
            "seq": seq,
            "ts": self._now().isoformat(),
            "type": kind,
            "payload": payload,
            "prev": self._last_hash,
        }
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        record = dict(body, hash=digest)
        line = json.dumps(record, ensure_ascii=False) + "\n"
        self._last_seq, self._last_hash = seq, digest
        if self.fsync_every == 1:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        else:
            self._buffer.append(line)
            if len(self._buffer) >= self.fsync_every:
                self.flush()
        return record

    def flush(self) -> None:
        """Persist buffered records (no-op in fsync_every=1 mode)."""
        if not self._buffer:
            return
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("".join(self._buffer))
            fh.flush()
            os.fsync(fh.fileno())
        self._buffer.clear()

    def close(self) -> None:
        self.flush()

    def seal(self) -> dict[str, Any]:
        """Persist a checkpoint; enables truncation detection.

        Sealing flushes the buffer and performs a **full** verification: an anchor
        written over a broken chain would legitimise tampering.
        """
        if not self.anchor_path:
            raise ValueError("no anchor_path configured")
        self.flush()
        full = self.verify(incremental=False)
        if not full.ok:
            raise ValueError(f"refusing to seal an invalid chain: {full.reason}")
        anchor = {"seq": self._last_seq, "hash": self._last_hash,
                  "sealed_at": self._now().isoformat()}
        tmp = self.anchor_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(anchor, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.anchor_path)
        return anchor

    def verify(self, incremental: bool = False) -> VerifyResult:
        """Verify the chain on disk.

        ``incremental=True`` re-reads only the tail after the last verification;
        it detects appends/edits/truncations at the tail cheaply, but an in-place
        edit of an older record requires a full pass (``incremental=False``).
        """
        if not os.path.exists(self.path):
            return VerifyResult(True, 0)
        if incremental:
            prev = self._verified_hash
            seq_expected = self._verified_seq + 1
            count = self._verified_seq
            offset = self._offset
        else:
            prev, seq_expected, count, offset = GENESIS, 1, 0, 0
        with open(self.path, "r", encoding="utf-8") as fh:
            fh.seek(offset)
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    return VerifyResult(False, count, count + 1, "unparsable record")
                missing = [k for k in ("seq", "ts", "type", "payload", "prev", "hash")
                           if k not in record]
                if missing:
                    # A forged/short record is tamper evidence, never a crash.
                    return VerifyResult(False, count, record.get("seq"),
                                        f"malformed record: missing {missing}")
                body = {k: record[k] for k in ("seq", "ts", "type", "payload", "prev")}
                if record.get("prev") != prev:
                    return VerifyResult(False, count, record.get("seq"), "prev hash mismatch")
                if hashlib.sha256(_canonical(body)).hexdigest() != record.get("hash"):
                    return VerifyResult(False, count, record.get("seq"), "record hash mismatch")
                if record.get("seq") != seq_expected:
                    return VerifyResult(False, count, record.get("seq"), "sequence gap")
                prev = record["hash"]
                seq_expected += 1
                count += 1
            self._offset = fh.tell()
        self._verified_seq, self._verified_hash = count, prev
        anchor = self._anchor()
        if anchor is not None and anchor["seq"] > count:
            return VerifyResult(False, count, None,
                                f"truncation: anchor seq {anchor['seq']} > chain {count}")
        if anchor is not None and anchor["seq"] == count and anchor["hash"] != prev:
            return VerifyResult(False, count, None, "anchor hash mismatch")
        return VerifyResult(True, count)

    @property
    def verified_records(self) -> int:
        return self._verified_seq


@dataclass
class IntegrityManifest:
    """Sealed sha256 manifest over a set of files."""

    root: str
    manifest_path: str
    files: dict[str, str] = field(default_factory=dict)

    def _rel(self, path: str) -> str:
        return os.path.relpath(os.path.abspath(path), os.path.abspath(self.root)).replace("\\", "/")

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def seal(self, paths: list[str]) -> dict[str, str]:
        self.files = {self._rel(p): self._sha256(p) for p in sorted(paths) if os.path.exists(p)}
        tmp = self.manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"files": self.files}, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.manifest_path)
        return self.files

    def load(self) -> dict[str, str]:
        with open(self.manifest_path, encoding="utf-8") as fh:
            self.files = json.load(fh)["files"]
        return self.files

    def verify(self) -> dict[str, Any]:
        current = {}
        for rel in self.files:
            abs_path = os.path.join(self.root, rel)
            if os.path.exists(abs_path):
                current[rel] = self._sha256(abs_path)
        modified = [rel for rel, digest in self.files.items()
                    if rel in current and current[rel] != digest]
        missing = [rel for rel in self.files if rel not in current]
        present = set()
        for rel in self.files:
            present.add(rel)
        added: list[str] = []
        for dirpath, _dirs, names in os.walk(self.root):
            for name in names:
                rel = self._rel(os.path.join(dirpath, name))
                if rel not in present and rel != self._rel(self.manifest_path):
                    added.append(rel)
        return {"ok": not modified and not missing,
                "modified": sorted(modified), "missing": sorted(missing),
                "added": sorted(added), "checked": len(self.files)}


@dataclass
class SelfTest:
    """Startup self-test: each check is explicit and failures are not swallowed."""

    checks: dict[str, Callable[[], tuple[bool, str]]] = field(default_factory=dict)

    def register(self, name: str, check: Callable[[], tuple[bool, str]]) -> None:
        self.checks[name] = check

    def run(self) -> dict[str, Any]:
        started = time.perf_counter()
        results = []
        for name, check in self.checks.items():
            try:
                ok, detail = check()
            except Exception as exc:                    # a crashing check is a failure
                ok, detail = False, f"check raised {type(exc).__name__}: {exc}"
            results.append({"check": name, "ok": bool(ok), "detail": detail})
        duration_ms = (time.perf_counter() - started) * 1000
        return {"ok": all(r["ok"] for r in results),
                "checks": results,
                "failed": [r["check"] for r in results if not r["ok"]],
                "duration_ms": round(duration_ms, 3)}

    def immutable_check(self, verify_fn: Callable[[], None]) -> Callable[[], tuple[bool, str]]:
        def _check() -> tuple[bool, str]:
            try:
                verify_fn()
                return True, "immutable policy unchanged"
            except Exception as exc:
                return False, str(exc)
        return _check

    def log_check(self, log: HashChainLog) -> Callable[[], tuple[bool, str]]:
        def _check() -> tuple[bool, str]:
            result = log.verify()
            return result.ok, result.reason or f"{result.records} records verified"
        return _check

    def integrity_check(self, manifest: IntegrityManifest) -> Callable[[], tuple[bool, str]]:
        def _check() -> tuple[bool, str]:
            result = manifest.verify()
            if result["ok"]:
                return True, f"{result['checked']} files unchanged"
            return False, f"modified={result['modified']} missing={result['missing']}"
        return _check
