"""Linux auditd parser/collector: grouping, normalization, rotation, partial lines."""

from __future__ import annotations

import json

from core.auditsource import AuditLogParser, LinuxAuditSource
from core.normalize import HostContext, Normalizer

EXEC = (
    'type=SYSCALL msg=audit(1763000000.100:100): arch=c000003e syscall=59 '
    'success=yes exit=0 a0=55d0 a1=55e0 a2=55f0 a3=8 items=2 ppid=1 pid=4242 '
    'auid=1000 uid=1000 gid=1000 euid=1000 comm="bash" '
    'exe="/usr/bin/bash" key="exec"'
)
EXECVE = 'type=EXECVE msg=audit(1763000000.100:100): argc=3 a0="ls" a1="-la" a2="/tmp"'
PATH = ('type=PATH msg=audit(1763000000.100:100): item=0 name="/usr/bin/ls" '
        'inode=123 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL')
PROCTITLE = 'type=PROCTITLE msg=audit(1763000000.100:100): proctitle=6C73C2A02D6C61'
CONNECT = (
    'type=SYSCALL msg=audit(1763000000.200:101): arch=c000003e syscall=42 '
    'success=yes exit=0 a0=3 a1=7ffd a2=16 a3=0 items=0 ppid=1 pid=4243 '
    'auid=1000 uid=1000 gid=1000 euid=1000 comm="curl" '
    'exe="/usr/bin/curl" key="connect"'
)
OPEN = (
    'type=SYSCALL msg=audit(1763000000.300:102): arch=c000003e syscall=257 '
    'success=yes exit=3 a0=ffffff9c a1=55d0 a2=0 a3=0 items=1 ppid=1 pid=4244 '
    'auid=1000 uid=1000 gid=1000 euid=1000 comm="cat" '
    'exe="/usr/bin/cat" key="open"'
)
SHADOW = ('type=PATH msg=audit(1763000000.300:102): item=0 name="/etc/shadow" '
          'inode=999 dev=08:01 mode=0100640 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL')


def _lines() -> list[str]:
    return [EXEC, EXECVE, PATH, PROCTITLE, CONNECT, OPEN, SHADOW]


def test_parser_groups_multiline_exec_and_keeps_numeric_fields():
    parser = AuditLogParser(flush_after_s=0)
    out = []
    for line in _lines():
        out.extend(parser.feed(line, now=0))
    out.extend(parser.flush())
    assert len(out) == 3
    first = out[0]
    assert first["exe"] == "/usr/bin/bash"
    assert first["pid"] == 4242
    assert first["ppid"] == 1
    assert first["uid"] == "1000"          # not hex-decoded to '\x10'
    assert first["cmdline"] == "ls -la /tmp"
    assert first["path"] == "/usr/bin/ls"
    assert first["key"] == "exec"
    assert out[1]["key"] == "connect"
    assert out[2]["path"] == "/etc/shadow"


def test_parser_derives_keys_from_syscall_when_auditd_key_missing():
    parser = AuditLogParser(flush_after_s=0)
    line = EXEC.replace(' key="exec"', "")
    parser.feed(line, now=0)
    out = parser.flush()
    assert out and out[0]["key"] == "exec"


def test_parser_flushes_final_group_after_idle():
    parser = AuditLogParser(flush_after_s=1.0)
    assert parser.feed(EXEC, now=0) == []
    assert parser.flush_expired(now=0.5) == []
    out = parser.flush_expired(now=2.0)
    assert len(out) == 1 and out[0]["pid"] == 4242


def test_normalizes_to_event_v3():
    parser = AuditLogParser(flush_after_s=0)
    for line in _lines()[:3]:
        parser.feed(line, now=0)
    raw = parser.flush()[0]
    normalizer = Normalizer(host=HostContext(host_id="h", os="linux",
                                             version="1", arch="x64"))
    event = normalizer.normalize("linux.auditd", raw)
    assert event.platform == "linux"
    assert event.category == "process.start"
    assert event.actor is not None and event.actor.pid == 4242
    assert event.object is not None and event.object.path == "/usr/bin/ls"


def test_collector_tails_new_lines_and_partial(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("\n".join(_lines()) + "\n", encoding="utf-8")
    source = LinuxAuditSource(str(path), flush_after_s=0)
    assert len(source.poll()) == 3
    assert source.poll() == []

    # Partial line: not consumed until the newline arrives.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(EXEC.replace("4242", "9999")[:40])
    assert source.poll() == []
    with path.open("a", encoding="utf-8") as fh:
        fh.write(EXEC.replace("4242", "9999")[40:] + "\n")
    out = source.poll()
    assert out and out[0]["pid"] == 9999


def test_collector_resets_after_truncation(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("\n".join(_lines()) + "\n", encoding="utf-8")
    source = LinuxAuditSource(str(path), flush_after_s=0)
    assert len(source.poll()) == 3
    source.close()
    path.write_text(EXEC.replace("4242", "7777") + "\n", encoding="utf-8")
    out = source.poll()
    assert out and out[0]["pid"] == 7777


def test_unknown_types_are_skipped_without_exception():
    parser = AuditLogParser(flush_after_s=0)
    parser.feed('type=DAEMON_START msg=audit(1.000:1): op=start', now=0)
    assert parser.flush() == []
