"""Linux kernel-level prevention via fanotify permission events.

Unlike auditd/eBPF telemetry, fanotify `FAN_OPEN_PERM` and
`FAN_OPEN_EXEC_PERM` let a privileged daemon *deny* a file open or an exec
before it completes. This is kernel enforcement without a kernel module and
without Microsoft signing.

Scope:
  * deny execution from writable directories by default;
  * deny writable opens of protected system files by default;
  * allow package managers so apt/dpkg/rpm can still update the system;
  * audit mode logs decisions without blocking (safe rollout).

Limitations:
  * requires root/CAP_SYS_ADMIN and a filesystem that supports fanotify marks;
  * it sees file/exec events, not network/process memory;
  * a root attacker can stop the daemon; this is not a kernel rootkit.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import select
import signal
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010
FAN_MARK_IGNORED_MASK = 0x00000020
FAN_OPEN_PERM = 0x00010000
FAN_OPEN_EXEC_PERM = 0x00040000
FAN_ALLOW = 0x01
FAN_DENY = 0x02
AT_FDCWD = -100

FANOTIFY_METADATA_VERSION = 3
FAN_EVENT_METADATA_LEN = 24  # struct fanotify_event_metadata on 64-bit


class _EventMetadata(ctypes.Structure):
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]


class _Response(ctypes.Structure):
    _fields_ = [("fd", ctypes.c_int32), ("response", ctypes.c_uint32)]


@dataclass
class GuardPolicy:
    mode: str = "audit"                 # audit | enforce
    mark_path: str = "/"
    deny_exec: list[str] = field(default_factory=lambda: [
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
    ])
    protect_write: list[str] = field(default_factory=lambda: [
        "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh/sshd_config",
        "/boot/", "/var/lib/aidf/", "/opt/aidf/",
    ])
    allow_write_processes: list[str] = field(default_factory=lambda: [
        "apt", "apt-get", "dpkg", "rpm", "dnf", "yum", "systemctl",
        "packagekitd", "snapd", "unattended-upgr",
    ])

    @classmethod
    def load(cls, path: str | Path | None = None) -> "GuardPolicy":
        if not path or not Path(path).exists():
            return cls()
        try:
            import tomllib
        except ModuleNotFoundError:  # pragma: no cover
            import tomli as tomllib  # type: ignore
        raw = Path(path).read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        data = tomllib.loads(raw.decode("utf-8"))
        guard = data.get("guard", {})
        cfg = cls()
        if "mode" in guard:
            cfg.mode = str(guard["mode"])
        if "mark_path" in guard:
            cfg.mark_path = str(guard["mark_path"])
        if "deny_exec" in guard:
            cfg.deny_exec = [str(x) for x in guard["deny_exec"]]
        if "protect_write" in guard:
            cfg.protect_write = [str(x) for x in guard["protect_write"]]
        if "allow_write_processes" in guard:
            cfg.allow_write_processes = [str(x) for x in guard["allow_write_processes"]]
        return cfg


def _under(path: str, prefixes: Iterable[str]) -> str | None:
    for prefix in prefixes:
        if path == prefix.rstrip("/") or path.startswith(prefix):
            return prefix
    return None


def _process_name(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _fd_writable(fd: int) -> bool:
    """Read open flags from /proc/self/fdinfo/<fd>; O_ACCMODE 3."""
    try:
        text = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="utf-8")
    except OSError:
        return False
    for line in text.splitlines():
        if line.startswith("flags:"):
            try:
                flags = int(line.split()[1], 8)
            except (IndexError, ValueError):
                return False
            return (flags & 0o3) != 0
    return False


@dataclass
class GuardDecision:
    allow: bool
    path: str
    pid: int
    process: str
    mask: int
    reason: str


class FanotifyGuard:
    def __init__(self, policy: GuardPolicy, out: str = "") -> None:
        self.policy = policy
        self.out_path = out
        self._libc = ctypes.CDLL(None, use_errno=True) if sys.platform == "linux" else None
        if self._libc is not None:
            self._libc.fanotify_init.restype = ctypes.c_int
            self._libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_int]
            self._libc.fanotify_mark.restype = ctypes.c_int
            self._libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint,
                                                 ctypes.c_uint64, ctypes.c_int,
                                                 ctypes.c_char_p]
        self._fd: int | None = None
        self._out_fh = None
        self._stop = False
        self.decisions = 0
        self.blocks = 0
        self.errors = 0

    def _emit(self, decision: GuardDecision) -> None:
        record = {
            "kind": "guard",
            "ts": time.time(),
            "pid": decision.pid,
            "process": decision.process,
            "path": decision.path,
            "mask": hex(decision.mask),
            "allow": decision.allow,
            "reason": decision.reason,
            "mode": self.policy.mode,
        }
        if self._out_fh is not None:
            self._out_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._out_fh.flush()
        else:
            print(json.dumps(record, ensure_ascii=False), flush=True)

    def decide(self, path: str, mask: int, pid: int, writable: bool = False) -> GuardDecision:
        process = _process_name(pid)
        allow = True
        reason = "allowed"
        if mask & FAN_OPEN_EXEC_PERM:
            hit = _under(path, self.policy.deny_exec)
            if hit:
                allow = False
                reason = f"exec under writable path: {hit}"
        elif mask & FAN_OPEN_PERM and writable:
            hit = _under(path, self.policy.protect_write)
            if hit:
                allowed_proc = process in self.policy.allow_write_processes
                if not allowed_proc:
                    allow = False
                    reason = f"write to protected path: {hit}"
                else:
                    reason = f"allowed package manager write: {process}"
        return GuardDecision(allow, path, pid, process, mask, reason)

    def start(self) -> None:
        if sys.platform != "linux" or self._libc is None:
            raise OSError("fanotify is Linux-only")
        flags = FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK
        fd = self._libc.fanotify_init(flags, os.O_RDONLY | getattr(os, "O_LARGEFILE", 0))
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, f"fanotify_init: {os.strerror(err)}")
        mask = FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM
        rc = self._libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                                     mask, AT_FDCWD, self.policy.mark_path.encode())
        if rc < 0:
            err = ctypes.get_errno()
            os.close(fd)
            raise OSError(err, f"fanotify_mark: {os.strerror(err)}")
        # Do not generate permission events for our own /proc lookups; otherwise
        # reading /proc/<pid>/comm or /proc/self/fdinfo can recurse into the guard.
        for ignored in ("/proc", "/sys", "/dev"):
            self._libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
                                     FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM,
                                     AT_FDCWD, ignored.encode())
        if self.out_path:
            Path(self.out_path).parent.mkdir(parents=True, exist_ok=True)
            self._out_fh = open(self.out_path, "a", encoding="utf-8")
        self._fd = fd

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        if self._fd is None:
            self.start()
        assert self._fd is not None
        buf = bytearray(64 * 1024)
        while not self._stop:
            ready, _, _ = select.select([self._fd], [], [], 0.5)
            if not ready:
                continue
            try:
                size = os.read(self._fd, len(buf))
            except BlockingIOError:
                continue
            except OSError as exc:
                if exc.errno in (errno.EINTR, errno.EAGAIN):
                    continue
                raise
            offset = 0
            while offset + FAN_EVENT_METADATA_LEN <= size:
                meta = _EventMetadata.from_buffer_copy(bytes(buf[offset:offset + FAN_EVENT_METADATA_LEN]))
                if meta.event_len < FAN_EVENT_METADATA_LEN or offset + meta.event_len > size:
                    break
                if meta.vers != FANOTIFY_METADATA_VERSION:
                    offset += meta.event_len
                    continue
                event_fd = meta.fd
                try:
                    path = os.readlink(f"/proc/self/fd/{event_fd}")
                    writable = _fd_writable(event_fd)
                    decision = self.decide(path, int(meta.mask), int(meta.pid), writable)
                    self.decisions += 1
                    if not decision.allow:
                        self.blocks += 1
                        self._emit(decision)
                    elif self.policy.mode == "audit" and decision.reason != "allowed":
                        self._emit(decision)
                    response = FAN_ALLOW if (decision.allow or self.policy.mode == "audit") else FAN_DENY
                    resp = _Response(event_fd, response)
                    os.write(self._fd, bytes(resp))
                except OSError as exc:
                    self.errors += 1
                    if not self.out_path:
                        print(json.dumps({"kind": "guard_error", "error": str(exc)}), flush=True)
                finally:
                    try:
                        os.close(event_fd)
                    except OSError:
                        pass
                offset += meta.event_len

    def close(self) -> None:
        self._stop = True
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        if self._out_fh is not None:
            try:
                self._out_fh.close()
            except OSError:
                pass
            self._out_fh = None


def run_guard(policy: GuardPolicy, out: str = "") -> int:
    guard = FanotifyGuard(policy, out=out)
    try:
        guard.start()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: guard.stop())
        if not out:
            print(json.dumps({"kind": "guard_ready", "mode": policy.mode,
                              "mark": policy.mark_path}), flush=True)
        guard.run()
    finally:
        guard.close()
    return 0
