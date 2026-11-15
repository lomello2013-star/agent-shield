"""Response actions (stage 7): suspend/resume, quarantine/restore, canary checks.

Safety rules:
  * every action goes through the confirmation gate (`core.confirm`); an
    unapproved action is refused, a destructive one without an operator is
    queued (never executed);
  * quarantine is reversible by construction: the original bytes are encrypted
    with AES-GCM, the manifest holds the sha256, and restore verifies both;
  * irreversible actions (`terminate`) are refused in this layer — the policy
    layer must require human approval, and this module has no such path;
  * actions are timed end-to-end so E10 (contain <= 5 s) is measurable.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.confirm import ConfirmationManager
from schemas.v3 import Action

REVERSIBLE_ACTIONS = {"suspend", "resume", "quarantine", "restore", "notify",
                      "block_network", "unblock_network"}
UNSUPPORTED_ACTIONS = {"unblock_network"}
QUARANTINE_MAGIC = b"AIDFQ1"

if sys.platform == "win32":
    from ctypes import wintypes

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class ActionError(RuntimeError):
    """Action refused or failed (never swallowed)."""


# --------------------------------------------------------------------- processes
class ProcessController:
    """Suspend/resume a process and its same-image launcher child.

    A Windows venv redirector runs the real interpreter as a child with the same
    image name; suspending only the stub would leave the workload running (the
    3.14-venv finding). The same-image rule is deliberately conservative: other
    children of a real workload are not touched.
    """

    def __init__(self) -> None:
        self._ntdll = None
        self._kernel32 = None
        self._suspended: dict[int, list[int]] = {}
        if sys.platform == "win32":
            self._ntdll = ctypes.WinDLL("ntdll")
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._kernel32.OpenProcess.restype = ctypes.c_void_p
            self._kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int,
                                                   ctypes.c_uint32]
            self._kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            self._kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
            self._kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32,
                                                                ctypes.c_uint32]
            self._kernel32.Process32FirstW.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
            self._kernel32.Process32NextW.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]

    @property
    def supported(self) -> bool:
        return sys.platform == "win32" or sys.platform.startswith("linux")

    def _handle(self, pid: int) -> Any:
        PROCESS_SUSPEND_RESUME = 0x0800
        handle = self._kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, int(pid))
        if not handle:
            raise ActionError(f"OpenProcess failed for pid {pid} "
                              f"(err={ctypes.get_last_error()})")
        return handle

    def _process_table(self) -> dict[int, tuple[int, str]]:
        """pid -> (parent_pid, exe_name); empty when enumeration is unavailable."""
        if sys.platform != "win32":
            return {}
        table: dict[int, tuple[int, str]] = {}
        snapshot = self._kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == INVALID_HANDLE_VALUE:
            return table
        try:
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            more = self._kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while more:
                table[int(entry.th32ProcessID)] = (
                    int(entry.th32ParentProcessID), str(entry.szExeFile))
                more = self._kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            self._kernel32.CloseHandle(snapshot)
        return table

    def _suspend_targets(self, pid: int) -> list[int]:
        """The pid plus direct children that share its image name (redirector-safe)."""
        pid = int(pid)
        table = self._process_table()
        if pid not in table:
            return [pid]
        image = table[pid][1].lower()
        children = sorted(child for child, (parent, exe) in table.items()
                          if parent == pid and exe.lower() == image and child != pid)
        return [pid, *children]

    def _suspend_one(self, pid: int) -> None:
        if sys.platform == "win32":
            handle = self._handle(pid)
            try:
                status = self._ntdll.NtSuspendProcess(handle)
                if status != 0:
                    raise ActionError(f"NtSuspendProcess failed: 0x{status & 0xFFFFFFFF:08X}")
            finally:
                self._kernel32.CloseHandle(handle)
        else:
            os.kill(int(pid), 19)          # SIGSTOP

    def _resume_one(self, pid: int) -> None:
        if sys.platform == "win32":
            handle = self._handle(pid)
            try:
                status = self._ntdll.NtResumeProcess(handle)
                if status != 0:
                    raise ActionError(f"NtResumeProcess failed: 0x{status & 0xFFFFFFFF:08X}")
            finally:
                self._kernel32.CloseHandle(handle)
        else:
            os.kill(int(pid), 18)          # SIGCONT

    def suspend(self, pid: int) -> list[int]:
        pid = int(pid)
        targets = self._suspend_targets(pid)
        paused: list[int] = []
        for target in targets:
            try:
                self._suspend_one(target)
                paused.append(target)
            except ActionError:
                if target == pid:          # the requested process must be suspended
                    raise
        self._suspended[pid] = paused
        return paused

    def resume(self, pid: int) -> list[int]:
        pid = int(pid)
        targets = self._suspended.pop(pid, [pid])
        resumed: list[int] = []
        for target in targets:
            try:
                self._resume_one(target)
                resumed.append(target)
            except ActionError:
                if target == pid:
                    raise
        return resumed


# -------------------------------------------------------------------- quarantine
@dataclass
class QuarantineEntry:
    quarantine_id: str
    original_path: str
    sha256: str
    size: int
    created_at: float
    reason: str


class QuarantineStore:
    """Encrypted, reversible quarantine with manifest and hash verification."""

    def __init__(self, root: str, key: bytes | None = None, key_path: str | None = None) -> None:
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        if key is None:
            if key_path is None:
                raise ValueError("either key or key_path is required")
            with open(key_path, "rb") as fh:
                key = fh.read()
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be 32 bytes")
        self._aead = AESGCM(key)
        self.manifest_path = os.path.join(self.root, "manifest.json")
        self._entries: dict[str, QuarantineEntry] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.manifest_path):
            return
        with open(self.manifest_path, "r", encoding="utf-8") as fh:
            for item in json.load(fh).get("entries", []):
                entry = QuarantineEntry(**item)
                self._entries[entry.quarantine_id] = entry

    def _save(self) -> None:
        tmp = self.manifest_path + ".tmp"
        payload = {"entries": [vars(e) for e in self._entries.values()]}
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.manifest_path)

    def _blob_path(self, quarantine_id: str) -> str:
        return os.path.join(self.root, f"{quarantine_id}.qtn")

    def put(self, path: str, reason: str = "") -> QuarantineEntry:
        src = os.path.abspath(path)
        if not os.path.exists(src):
            raise ActionError(f"file not found: {path}")
        if os.path.islink(src):
            raise ActionError("refusing to quarantine a symlink")
        data = open(src, "rb").read()
        digest = hashlib.sha256(data).hexdigest()
        qid = uuid.uuid4().hex
        nonce = os.urandom(12)
        blob = QUARANTINE_MAGIC + nonce + self._aead.encrypt(nonce, data, qid.encode())
        blob_path = self._blob_path(qid)
        with open(blob_path, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        entry = QuarantineEntry(quarantine_id=qid, original_path=src, sha256=digest,
                                size=len(data), created_at=time.time(), reason=reason)
        self._entries[qid] = entry
        self._save()
        os.remove(src)
        return entry

    def restore(self, quarantine_id: str, target: str | None = None) -> str:
        entry = self._entries.get(quarantine_id)
        if entry is None:
            raise ActionError(f"unknown quarantine id: {quarantine_id}")
        dest = os.path.abspath(target or entry.original_path)
        if os.path.exists(dest):
            raise ActionError(f"refusing to overwrite existing file: {dest}")
        blob = open(self._blob_path(quarantine_id), "rb").read()
        if not blob.startswith(QUARANTINE_MAGIC):
            raise ActionError("quarantine blob has bad magic")
        nonce = blob[len(QUARANTINE_MAGIC):len(QUARANTINE_MAGIC) + 12]
        ciphertext = blob[len(QUARANTINE_MAGIC) + 12:]
        try:
            data = self._aead.decrypt(nonce, ciphertext, quarantine_id.encode())
        except Exception as exc:
            raise ActionError(f"quarantine blob failed authentication: {exc}") from exc
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            raise ActionError("restored content hash mismatch")
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.remove(self._blob_path(quarantine_id))
        del self._entries[quarantine_id]
        self._save()
        return dest

    def list(self) -> list[QuarantineEntry]:
        return list(self._entries.values())

    def verify(self, quarantine_id: str) -> bool:
        entry = self._entries.get(quarantine_id)
        if entry is None:
            return False
        blob_path = self._blob_path(quarantine_id)
        if not os.path.exists(blob_path):
            return False
        blob = open(blob_path, "rb").read()
        nonce = blob[len(QUARANTINE_MAGIC):len(QUARANTINE_MAGIC) + 12]
        try:
            data = self._aead.decrypt(nonce, blob[len(QUARANTINE_MAGIC) + 12:],
                                      quarantine_id.encode())
        except Exception:
            return False
        return hashlib.sha256(data).hexdigest() == entry.sha256


# ------------------------------------------------------------------------ canary
@dataclass
class CanaryStore:
    root: str
    files: list[str] = field(default_factory=list)

    def create(self, count: int = 3) -> list[str]:
        os.makedirs(self.root, exist_ok=True)
        out = []
        for i in range(count):
            path = os.path.join(self.root, f"canary_{i}.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"aidf-canary-{i}-{uuid.uuid4()}\n")
            out.append(path)
        self.files = out
        return out

    def check(self) -> list[str]:
        """Return canaries that were deleted or modified (tamper evidence)."""
        broken = []
        for path in self.files:
            if not os.path.exists(path):
                broken.append(path)
                continue
            try:
                with open(path, encoding="utf-8") as fh:
                    if not fh.read().startswith("aidf-canary-"):
                        broken.append(path)
            except OSError:
                broken.append(path)
        return broken


# ---------------------------------------------------------------------- firewall
class FirewallController:
    """User-mode network block via Windows Firewall (no kernel driver).

    This is post-detection containment, not a WFP callout. Rules are named and
    reversible with ``unblock``.
    """

    def __init__(self, runner=None) -> None:
        self._run = runner or __import__("subprocess").run
        self.rules: dict[str, str] = {}

    @staticmethod
    def _parse(target: str) -> tuple[str, str]:
        text = str(target).strip()
        if not text:
            raise ActionError("empty firewall target")
        ip, _, port = text.rpartition(":")
        if ip and port.isdigit():
            return ip, port
        return text, "any"

    def block(self, target: str, name: str | None = None) -> str:
        if sys.platform != "win32":
            raise ActionError("Windows Firewall response is Windows-only")
        ip, port = self._parse(target)
        rule = name or f"AIDF-block-{uuid.uuid4().hex[:12]}"
        argv = ["netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule}", "dir=out", "action=block",
                f"remoteip={ip}", f"remoteport={port}", "protocol=TCP"]
        completed = self._run(argv, capture_output=True, text=True, timeout=30)
        if getattr(completed, "returncode", 1) != 0:
            raise ActionError(f"firewall add failed: {getattr(completed, 'stderr', '')[:200]}")
        self.rules[rule] = target
        return rule

    def unblock(self, rule: str) -> None:
        if sys.platform != "win32":
            raise ActionError("Windows Firewall response is Windows-only")
        completed = self._run(["netsh", "advfirewall", "firewall", "delete", "rule",
                               f"name={rule}"], capture_output=True, text=True, timeout=30)
        if getattr(completed, "returncode", 1) != 0:
            raise ActionError(f"firewall delete failed: {getattr(completed, 'stderr', '')[:200]}")
        self.rules.pop(rule, None)


# ---------------------------------------------------------------------- executor
@dataclass
class ExecutionResult:
    action: Action
    status: str            # executed | failed | refused
    error: str = ""
    duration_ms: float = 0.0


class ResponseExecutor:
    """Executes *reversible* actions only, always behind the confirmation gate."""

    def __init__(self, confirmations: ConfirmationManager,
                 processes: ProcessController | None = None,
                 quarantine: QuarantineStore | None = None,
                 firewall: FirewallController | None = None,
                 clock=time.perf_counter) -> None:
        self.confirmations = confirmations
        self.processes = processes or ProcessController()
        self.quarantine = quarantine
        self.firewall = firewall or FirewallController()
        self.clock = clock

    def execute(self, action: Action) -> ExecutionResult:
        if action.type == "terminate":
            return ExecutionResult(action, "refused",
                                   "irreversible action requires human approval path")
        if action.type in UNSUPPORTED_ACTIONS:
            return ExecutionResult(action, "failed",
                                   f"action not supported in user-mode: {action.type}")
        if action.requires_confirmation:
            if action.confirmation_id is None:
                return ExecutionResult(action, "refused", "confirmation_required")
            if not self.confirmations.executable(action.confirmation_id):
                return ExecutionResult(action, "refused", "confirmation_not_approved")
        t0 = self.clock()
        try:
            if action.type == "suspend":
                self.processes.suspend(int(action.target))
                status = "executed"
            elif action.type == "resume":
                self.processes.resume(int(action.target))
                status = "executed"
            elif action.type == "quarantine":
                if self.quarantine is None:
                    raise ActionError("quarantine store not configured")
                self.quarantine.put(action.target, action.platform_effect)
                status = "executed"
            elif action.type == "restore":
                if self.quarantine is None:
                    raise ActionError("quarantine store not configured")
                self.quarantine.restore(action.target)
                status = "executed"
            elif action.type == "notify":
                status = "executed"
            elif action.type == "block_network":
                rule = self.firewall.block(action.target)
                action = action.model_copy(update={"target": rule})
                status = "executed"
            elif action.type == "unblock_network":
                self.firewall.unblock(action.target)
                status = "executed"
            else:
                raise ActionError(f"unknown action type: {action.type}")
            error = ""
        except ActionError as exc:
            status, error = "failed", str(exc)
        duration_ms = (self.clock() - t0) * 1000.0
        updated = action.model_copy(update={"status": status if status != "refused" else "rejected"})
        return ExecutionResult(updated, status, error, round(duration_ms, 3))
