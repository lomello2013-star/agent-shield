import pytest

from core.normalize import ADAPTERS, HostContext, NormalizationError, Normalizer

HOST = HostContext(host_id="host-1", os="windows", version="10.0.19045", arch="x64",
                   kernel="10.0.19045")


def normalizer(tmp_path=None, **kwargs):
    return Normalizer(host=HOST, now_fn=lambda: __import__("datetime").datetime(
        2026, 11, 12, 12, 0, tzinfo=__import__("datetime").timezone.utc), **kwargs)


def test_etw_ti_record_normalizes():
    n = normalizer()
    ev = n.normalize("win.etw.ti", {
        "process_id": 512, "parent_id": 4, "process_name": r"C:\Temp\malware.exe",
        "cmdline": "malware.exe -x", "target": r"C:\Windows\System32\lsass.exe",
        "category": "process.access", "action": "open_process", "keyword": "0x1",
    })
    assert ev.platform == "windows" and ev.source == "win.etw.ti"
    assert ev.category == "process.access"
    assert ev.actor.pid == 512 and ev.actor.name == "malware.exe"
    assert ev.actor.cmdline_hash and len(ev.actor.cmdline_hash) == 64
    assert ev.object.path.endswith("lsass.exe")
    assert ev.host.host_id == "host-1"


def test_etw_ti_missing_required_field_raises():
    with pytest.raises(NormalizationError) as exc:
        normalizer().normalize("win.etw.ti", {"process_id": 1})
    assert exc.value.field_name == "process_name"


def test_linux_ebpf_syscall_mapping():
    n = normalizer()
    for syscall, expected in [("execve", "process.start"), ("openat", "file.write"),
                              ("connect", "net.connect"), ("unlink", "file.delete")]:
        ev = n.normalize("linux.ebpf", {"pid": 10, "ppid": 1, "comm": "bash",
                                        "exe": "/usr/bin/bash", "syscall": syscall})
        assert ev.category == expected
        assert ev.platform == "linux"


def test_linux_ebpf_unmapped_syscall_rejected():
    with pytest.raises(NormalizationError) as exc:
        normalizer().normalize("linux.ebpf", {"pid": 10, "comm": "x", "syscall": "futex"})
    assert "unmapped syscall" in exc.value.reason


def test_amsi_adapter():
    ev = normalizer().normalize("win.amsi", {
        "app_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "content_name": "ScriptBlock", "result": 1, "process_id": 77,
    })
    assert ev.category == "script.execute" and ev.layer == "script"
    assert ev.platform_data["amsi_result"] == 1


def test_auditd_adapter_and_key_mapping():
    ev = normalizer().normalize("linux.auditd", {"exe": "/bin/sh", "pid": 5, "key": "exec",
                                                 "path": "/tmp/x.sh"})
    assert ev.category == "process.start"
    assert ev.platform_data["audit_key"] == "exec"


def test_auditd_unknown_key_rejected():
    with pytest.raises(NormalizationError):
        normalizer().normalize("linux.auditd", {"exe": "/bin/sh", "pid": 5, "key": "wat"})


def test_unknown_source_rejected():
    with pytest.raises(NormalizationError):
        normalizer().normalize("macos.endpoint", {})


def test_bad_timestamp_falls_back_and_is_counted():
    n = normalizer()
    ev = n.normalize("linux.ebpf", {"pid": 1, "comm": "x", "syscall": "execve",
                                    "ts": "not-a-date"})
    assert ev.ts_event == ev.ts_ingest
    assert n.stats()["bad_timestamps"] == 1
    assert n.counters.get("bad_timestamp") == 1


def test_epoch_timestamp_is_used():
    ev = normalizer().normalize("linux.ebpf", {"pid": 1, "comm": "x", "syscall": "execve",
                                               "ts": 1700000000})
    assert ev.ts_event.year == 2023


def test_invalid_nested_value_becomes_normalization_error():
    with pytest.raises(NormalizationError):
        normalizer().normalize("win.etw.ti", {"process_id": "not-an-int",
                                              "process_name": r"C:\a.exe"})


def test_quarantine_writes_record_and_counts(tmp_path):
    qpath = tmp_path / "quarantine" / "bad.jsonl"
    n = normalizer(quarantine_path=str(qpath))
    assert n.normalize_or_quarantine("win.etw.ti", {"process_id": 1}) is None
    assert qpath.exists()
    line = qpath.read_text(encoding="utf-8").strip()
    assert "missing required field" in line
    assert n.stats()["quarantined"] == 1


def test_quarantine_without_path_still_counts():
    n = normalizer()
    assert n.normalize_or_quarantine("win.etw.ti", {}) is None
    assert n.stats()["quarantined"] == 1


def test_all_adapters_declare_platform_and_layer():
    for source, adapter in ADAPTERS.items():
        assert adapter.source == source
        assert adapter.platform in ("windows", "linux")
        assert adapter.layer in ("kernel", "script", "user", "network", "memory")


def test_pii_flags_and_cmdline_truncation():
    ev = normalizer().normalize("win.etw.ti", {
        "process_id": 1, "process_name": r"C:\a.exe", "cmdline": "A" * 500,
    })
    assert ev.pii.cmdline_hashed is True
    assert len(ev.actor.cmdline_redacted) == 200


def test_linux_lsm_adapter_maps_credential_read():
    ev = normalizer().normalize("linux.lsm", {"pid": 42, "ppid": 1, "comm": "cat",
                                              "path": "/etc/shadow", "hook": "file_open"})
    assert ev.platform == "linux" and ev.category == "file.read"
    assert ev.object.path == "/etc/shadow"
    assert ev.platform_data["lsm_hook"] == "file_open"
    assert ev.actor.pid == 42


def test_linux_lsm_requires_path():
    with pytest.raises(NormalizationError) as exc:
        normalizer().normalize("linux.lsm", {"pid": 1, "comm": "x"})
    assert exc.value.field_name == "path"


def test_linux_net_adapter_maps_connect():
    ev = normalizer().normalize("linux.net", {"pid": 7, "comm": "curl",
                                              "daddr": "10.0.0.9", "dport": 4444})
    assert ev.category == "net.connect" and ev.layer == "network"
    assert ev.object.port == 4444 and ev.object.ip == "10.0.0.9"
    assert ev.platform_data["hook"] == "cgroup/connect4"


def test_linux_net_requires_port():
    with pytest.raises(NormalizationError) as exc:
        normalizer().normalize("linux.net", {"pid": 7, "comm": "x", "daddr": "1.2.3.4"})
    assert exc.value.field_name == "dport"


def test_win_eventlog_builds_actor_from_process_id():
    """Sysmon process events must carry actor_pid so Windows suspend has a target."""
    ev = normalizer().normalize("win.eventlog", {
        "category": "process.start", "action": "start",
        "path": r"C:\Temp\evil.exe", "event_id": 1,
        "provider": "Microsoft-Windows-Sysmon", "record_id": 1,
        "ts": "2026-11-14T00:00:00Z",
        "process_id": 4242, "parent_id": 4,
        "image": r"C:\Temp\evil.exe", "cmdline": "evil.exe -x", "data": {},
    })
    assert ev.actor is not None
    assert ev.actor.pid == 4242
    assert ev.actor.path == r"C:\Temp\evil.exe"
    assert ev.object.type == "process"
    assert ev.platform_data["cmdline"] == "evil.exe -x"
