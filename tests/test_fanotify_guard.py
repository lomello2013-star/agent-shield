"""fanotify guard policy decisions and config."""

from __future__ import annotations

from core.fanotify_guard import FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM, FanotifyGuard, GuardPolicy


def test_exec_from_writable_path_is_denied():
    p = GuardPolicy(mode="enforce")
    d = FanotifyGuard(p).decide("/tmp/evil.sh", FAN_OPEN_EXEC_PERM, 1234)
    assert d.allow is False
    assert "writable" in d.reason


def test_exec_from_usr_is_allowed():
    from core.fanotify_guard import FanotifyGuard
    d = FanotifyGuard(GuardPolicy(mode="enforce")).decide(
        "/usr/bin/ls", FAN_OPEN_EXEC_PERM, 1234)
    assert d.allow is True


def test_protected_write_is_denied():
    from core.fanotify_guard import FanotifyGuard
    d = FanotifyGuard(GuardPolicy(mode="enforce")).decide(
        "/etc/shadow", FAN_OPEN_PERM, 1234, writable=True)
    assert d.allow is False
    assert "protected" in d.reason


def test_package_manager_write_is_allowed(monkeypatch):
    from core.fanotify_guard import FanotifyGuard
    monkeypatch.setattr("core.fanotify_guard._process_name", lambda pid: "dpkg")
    d = FanotifyGuard(GuardPolicy(mode="enforce")).decide(
        "/etc/shadow", FAN_OPEN_PERM, 1234, writable=True)
    assert d.allow is True


def test_toml_policy_loads(tmp_path):
    path = tmp_path / "guard.toml"
    path.write_text("""
[guard]
mode = "enforce"
mark_path = "/data"
deny_exec = ["/data/tmp/"]
protect_write = ["/data/etc/"]
allow_write_processes = ["apt"]
""", encoding="utf-8")
    p = GuardPolicy.load(path)
    assert p.mode == "enforce" and p.mark_path == "/data"
    assert p.deny_exec == ["/data/tmp/"]
