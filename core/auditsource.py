"""auditd log source: Linux kernel audit records -> Event v3 raw records.

The collector is read-only: it tails ``/var/log/audit/audit.log`` (or another
path), groups the multi-line records for one audit message, and converts the
useful ones to the raw shape understood by ``core.normalize._linux_auditd``.

Why a separate collector and not an eBPF program:

* auditd is available on every mainstream Linux and needs no kernel headers;
* it covers exec/connect/open/delete/persistence for hosts where loading BPF is
  not possible (locked-down kernels, containers, old distros);
* the source stays testable on Windows/WSL with a fixture file.

Limitations are explicit: auditd must be configured with rules that set a
``key`` (or the syscall must be one of the well-known ones), and the collector
never elevates or changes auditd configuration.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

AUDIT_MSG_RE = re.compile(r"msg=audit\((?P<ts>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
FIELD_RE = re.compile(r'(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>"(?:\\.|[^"\\])*"|\S+)')
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")

# x86_64 syscall numbers. A missing key is common when auditd rules are minimal;
# mapping the dangerous primitives keeps the collector useful without them.
SYSCALL_KEYS: dict[int, str] = {
    59: "exec", 322: "exec",          # execve, execveat
    42: "connect",                    # connect
    2: "open", 257: "open",           # open, openat
    87: "delete", 263: "delete",      # unlink, unlinkat
}

# audit record types that carry a useful process identity without a SYSCALL line.
TYPE_KEYS: dict[str, str] = {
    "USER_CMD": "exec",
    "USER_AUTH": "persistence",
    "USER_ACCT": "persistence",
    "USER_LOGIN": "persistence",
    "USER_START": "persistence",
    "USER_END": "persistence",
    "SERVICE_START": "persistence",
    "SERVICE_STOP": "persistence",
    "CONFIG_CHANGE": "persistence",
    "AVC": "open",
    "SECCOMP": "exec",
}

DEFAULT_PATH = "/var/log/audit/audit.log"


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
        value = value.replace('\\"', '"').replace("\\\\", "\\")
    return value


def _decode_hex(value: str) -> str | None:
    """auditd hex-encodes non-printable EXECVE args and PROCTITLE."""
    if len(value) < 2 or len(value) % 2 or not HEX_RE.fullmatch(value):
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    if b"\x00" in raw:
        return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    text = raw.decode("utf-8", "replace")
    return text if all(ch.isprintable() or ch in "\t " for ch in text) else None


def _field_value(value: str) -> str:
    # Do NOT hex-decode every field: decimal syscall/pid/uid values such as
    # "59" or "4242" are valid hex-looking strings. EXECVE args are decoded
    # contextually below; PROCTITLE is decoded explicitly.
    return _unquote(value)


def parse_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in FIELD_RE.finditer(line):
        fields[match.group("key")] = _field_value(match.group("value"))
    return fields


@dataclass
class _Group:
    audit_id: str
    ts: float
    lines: list[str] = field(default_factory=list)
    fields_by_type: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.monotonic)

    def add(self, line: str) -> None:
        self.lines.append(line)
        type_match = re.search(r"\btype=([A-Z0-9_]+)", line)
        if type_match is None:
            return
        type_name = type_match.group(1)
        self.fields_by_type.setdefault(type_name, []).append(parse_fields(line))


def _first(groups: dict[str, list[dict[str, str]]], *names: str) -> dict[str, str]:
    for name in names:
        records = groups.get(name)
        if records:
            return records[0]
    return {}


def _all(groups: dict[str, list[dict[str, str]]], name: str) -> list[dict[str, str]]:
    return groups.get(name, [])


def _exec_args(groups: dict[str, list[dict[str, str]]]) -> str:
    for record in _all(groups, "EXECVE"):
        args: list[str] = []
        argc = int(record.get("argc", "0") or 0)
        for index in range(argc):
            value = record.get(f"a{index}")
            if value is None:
                break
            args.append(value)
        if args:
            return " ".join(args)
    return ""


def _proctitle(groups: dict[str, list[dict[str, str]]]) -> str:
    record = _first(groups, "PROCTITLE")
    value = record.get("proctitle") or ""
    if not value:
        return ""
    if HEX_RE.fullmatch(value) and len(value) % 2 == 0:
        decoded = _decode_hex(value)
        if decoded:
            return decoded
    return value


def _path(groups: dict[str, list[dict[str, str]]]) -> str:
    for record in _all(groups, "PATH"):
        name = record.get("name") or ""
        if name and name != "(null)" and not name.startswith("("):
            return name
    return ""


def _key_for(syscall: dict[str, str], type_names: Iterable[str]) -> str:
    explicit = str(syscall.get("key") or "").strip()
    if explicit:
        return explicit
    try:
        number = int(syscall.get("syscall", ""))
    except (TypeError, ValueError):
        number = -1
    if number in SYSCALL_KEYS:
        return SYSCALL_KEYS[number]
    for type_name in type_names:
        if type_name in TYPE_KEYS:
            return TYPE_KEYS[type_name]
    return ""


def group_to_raw(group: _Group) -> dict | None:
    """Convert one grouped audit message to the `linux.auditd` raw shape."""
    groups = group.fields_by_type
    syscall = _first(groups, "SYSCALL", "SECCOMP")
    type_names = list(groups)
    key = _key_for(syscall, type_names)
    if not key:
        return None

    pid_text = syscall.get("pid") or _first(groups, "USER_CMD", "SERVICE_START",
                                             "SERVICE_STOP").get("pid")
    if not pid_text:
        return None
    try:
        pid = int(pid_text)
    except ValueError:
        return None

    exe = syscall.get("exe") or ""
    comm = syscall.get("comm") or ""
    if not exe:
        exe = _first(groups, "USER_CMD", "SERVICE_START", "SERVICE_STOP").get("exe") or ""
    if not exe:
        # auditd sometimes omits exe on older kernels; comm is still an identity.
        exe = comm or _path(groups)
    if not exe:
        return None

    ppid = syscall.get("ppid")
    uid = syscall.get("uid") or syscall.get("auid")
    cmdline = _exec_args(groups) or _proctitle(groups)
    if not cmdline:
        cmdline = _first(groups, "USER_CMD").get("cmd") or ""
    path = _path(groups)
    if not path:
        path = _first(groups, "SERVICE_START", "SERVICE_STOP").get("unit") or ""

    raw = {
        "exe": exe,
        "pid": pid,
        "ppid": int(ppid) if ppid and str(ppid).isdigit() else None,
        "uid": uid,
        "cmdline": cmdline,
        "path": path or None,
        "key": key,
        "type": type_names[0] if type_names else "SYSCALL",
        "ts": group.ts,
    }
    # Keep the original syscall number for platform_data/debugging without
    # breaking the adapter's strict required fields.
    if "syscall" in syscall:
        raw["syscall_number"] = syscall["syscall"]
    return raw


class AuditLogParser:
    """Group auditd lines by `audit(ts:serial)` and flush complete groups.

    auditd writes all lines of one event contiguously; a new audit id therefore
    closes the previous group. The final group is flushed by ``poll`` after a
    short idle period (or explicitly by tests).
    """

    def __init__(self, flush_after_s: float = 1.0) -> None:
        self.flush_after_s = flush_after_s
        self._pending: dict[str, _Group] = {}
        self._order: list[str] = []

    def feed(self, line: str, now: float | None = None) -> list[dict]:
        match = AUDIT_MSG_RE.search(line)
        if match is None:
            return []
        audit_id = f"{match.group('ts')}:{match.group('serial')}"
        current = self._pending.get(audit_id)
        if current is None:
            if self._order:
                previous_id = self._order[-1]
                # A new audit id means the previous contiguous message is done.
                if audit_id != previous_id:
                    out = self._flush(previous_id)
                    return out + self._start(audit_id, match, line, now)
            return self._start(audit_id, match, line, now)
        current.add(line)
        return []

    def _start(self, audit_id: str, match: re.Match, line: str,
               now: float | None) -> list[dict]:
        group = _Group(audit_id=audit_id, ts=float(match.group("ts")),
                       first_seen=time.monotonic() if now is None else now)
        group.add(line)
        self._pending[audit_id] = group
        self._order.append(audit_id)
        return []

    def _flush(self, audit_id: str) -> list[dict]:
        group = self._pending.pop(audit_id, None)
        try:
            self._order.remove(audit_id)
        except ValueError:
            pass
        if group is None:
            return []
        raw = group_to_raw(group)
        return [raw] if raw is not None else []

    def flush_expired(self, now: float | None = None) -> list[dict]:
        now = time.monotonic() if now is None else now
        out: list[dict] = []
        for audit_id in list(self._order):
            group = self._pending.get(audit_id)
            if group is not None and now - group.first_seen >= self.flush_after_s:
                out.extend(self._flush(audit_id))
        return out

    def flush(self) -> list[dict]:
        out: list[dict] = []
        for audit_id in list(self._order):
            out.extend(self._flush(audit_id))
        return out


class LinuxAuditSource:
    """Read-only tailer for auditd's text log."""

    name = "linux.auditd"

    def __init__(self, path: str = DEFAULT_PATH, flush_after_s: float = 1.0,
                 max_bytes_per_poll: int = 2 * 1024 * 1024) -> None:
        self.path = Path(path)
        self.parser = AuditLogParser(flush_after_s=flush_after_s)
        self.max_bytes_per_poll = max_bytes_per_poll
        self._offset = 0
        self._inode: int | None = None
        self._partial = b""
        self._fh = None
        self._fh_inode: int | None = None
        self.calls = 0
        self.last_read_bytes = 0
        self.last_error = ""
        self.last_poll_ms = 0.0

    def _open_if_needed(self) -> bool:
        try:
            st = self.path.stat()
        except OSError as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False
        if self._fh is not None and self._fh_inode == st.st_ino:
            return True
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
        try:
            self._fh = self.path.open("rb")
        except OSError as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False
        self._fh_inode = st.st_ino
        # New inode or truncation: start from the beginning of the new file.
        if self._inode != st.st_ino or st.st_size < self._offset:
            self._offset = 0
            self._partial = b""
        self._inode = st.st_ino
        return True

    def poll(self) -> list[dict]:
        import time as _time
        started = _time.perf_counter()
        self.calls += 1
        if not self._open_if_needed():
            return []
        assert self._fh is not None
        try:
            self._fh.seek(self._offset)
            data = self._fh.read(self.max_bytes_per_poll)
        except OSError as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return []
        self.last_read_bytes = len(data)
        if not data:
            self.last_poll_ms = (_time.perf_counter() - started) * 1000
            return self.parser.flush_expired()
        data = self._partial + data
        last_nl = data.rfind(b"\n")
        if last_nl < 0:
            self._partial = data
            self.last_poll_ms = (_time.perf_counter() - started) * 1000
            return []
        complete = data[: last_nl + 1]
        self._partial = data[last_nl + 1:]
        self._offset += len(complete)
        out: list[dict] = []
        for line in complete.splitlines():
            if not line.strip():
                continue
            out.extend(self.parser.feed(line.decode("utf-8", "replace")))
        out.extend(self.parser.flush_expired())
        self.last_poll_ms = (_time.perf_counter() - started) * 1000
        self.last_error = ""
        return out

    def stats(self) -> dict:
        return {"path": str(self.path), "calls": self.calls,
                "offset": self._offset, "last_read_bytes": self.last_read_bytes,
                "last_poll_ms": round(self.last_poll_ms, 3),
                "last_error": self.last_error}

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
