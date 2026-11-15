import hashlib
import os
import subprocess
import sys
import time
import uuid

import pytest

from core.confirm import ConfirmationManager
from core.response import (
    ActionError,
    CanaryStore,
    ProcessController,
    QuarantineStore,
    ResponseExecutor,
)
from schemas.v3 import Action

KEY = b"k" * 32


def make_action(action_type="notify", target="x", requires_confirmation=False,
                confirmation_id=None, reversible=True):
    return Action.model_validate({
        "action_id": str(uuid.uuid4()), "trace_id": str(uuid.uuid4()),
        "verdict_id": str(uuid.uuid4()), "type": action_type, "target": target,
        "reversible": reversible, "requires_confirmation": requires_confirmation,
        "confirmation_id": str(confirmation_id) if confirmation_id else None,
        "platform_effect": "test",
    })


# ---------------------------------------------------------------- quarantine
def test_quarantine_roundtrip_restores_identical_bytes(tmp_path):
    store = QuarantineStore(str(tmp_path / "q"), key=KEY)
    original = tmp_path / "malware.bin"
    payload = b"MZ" + os.urandom(1024)
    original.write_bytes(payload)

    entry = store.put(str(original), "test")
    assert not original.exists()
    assert entry.sha256 == hashlib.sha256(payload).hexdigest()
    assert store.list() and store.verify(entry.quarantine_id)

    dest = store.restore(entry.quarantine_id)
    assert open(dest, "rb").read() == payload
    assert store.list() == []


def test_quarantine_manifest_survives_restart(tmp_path):
    store = QuarantineStore(str(tmp_path / "q"), key=KEY)
    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    entry = store.put(str(f))
    reopened = QuarantineStore(str(tmp_path / "q"), key=KEY)
    assert [e.quarantine_id for e in reopened.list()] == [entry.quarantine_id]
    assert reopened.verify(entry.quarantine_id)


def test_restore_refuses_to_overwrite(tmp_path):
    store = QuarantineStore(str(tmp_path / "q"), key=KEY)
    f = tmp_path / "a.txt"
    f.write_text("data", encoding="utf-8")
    entry = store.put(str(f))
    f.write_text("new", encoding="utf-8")
    with pytest.raises(ActionError):
        store.restore(entry.quarantine_id)


def test_tampered_blob_fails_authentication(tmp_path):
    store = QuarantineStore(str(tmp_path / "q"), key=KEY)
    f = tmp_path / "a.txt"
    f.write_text("data", encoding="utf-8")
    entry = store.put(str(f))
    blob_path = os.path.join(store.root, f"{entry.quarantine_id}.qtn")
    blob = bytearray(open(blob_path, "rb").read())
    blob[-1] ^= 0xFF
    open(blob_path, "wb").write(bytes(blob))
    assert store.verify(entry.quarantine_id) is False
    with pytest.raises(ActionError):
        store.restore(entry.quarantine_id)


def test_quarantine_missing_file_and_bad_key(tmp_path):
    store = QuarantineStore(str(tmp_path / "q"), key=KEY)
    with pytest.raises(ActionError):
        store.put(str(tmp_path / "nope.bin"))
    with pytest.raises(ValueError):
        QuarantineStore(str(tmp_path / "q2"), key=b"short")


def test_quarantine_rejects_symlink(tmp_path, monkeypatch):
    store = QuarantineStore(str(tmp_path / "q"), key=KEY)
    target = tmp_path / "real.txt"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        # Unprivileged Windows cannot create symlinks; simulate the flag so the
        # guard is still exercised and the test count stays deterministic.
        link.write_text("x", encoding="utf-8")
        monkeypatch.setattr(os.path, "islink",
                            lambda p: os.fspath(p) == os.fspath(link))
    with pytest.raises(ActionError):
        store.put(str(link))


# --------------------------------------------------------------------- canary
def test_canary_detects_delete_and_modify(tmp_path):
    store = CanaryStore(str(tmp_path / "canary"))
    files = store.create(3)
    assert len(files) == 3 and store.check() == []
    os.remove(files[0])
    with open(files[1], "w", encoding="utf-8") as fh:
        fh.write("tampered")
    broken = store.check()
    assert files[0] in broken and files[1] in broken


# ------------------------------------------------------------------- executor
def test_executor_notify_executes(tmp_path):
    ex = ResponseExecutor(ConfirmationManager())
    result = ex.execute(make_action("notify"))
    assert result.status == "executed" and result.duration_ms >= 0


def test_executor_refuses_without_confirmation(tmp_path):
    ex = ResponseExecutor(ConfirmationManager())
    result = ex.execute(make_action("suspend", target="1234", requires_confirmation=True))
    assert result.status == "refused" and result.error == "confirmation_required"


def test_executor_refuses_unapproved_confirmation():
    mgr = ConfirmationManager()
    conf = mgr.request("act")
    mgr.resolve(conf.confirmation_id, "rejected")
    ex = ResponseExecutor(mgr)
    result = ex.execute(make_action("suspend", target="1234", requires_confirmation=True,
                                    confirmation_id=conf.confirmation_id))
    assert result.status == "refused" and result.error == "confirmation_not_approved"


def test_executor_quarantines_with_approved_confirmation(tmp_path):
    mgr = ConfirmationManager()
    conf = mgr.request("act")
    mgr.resolve(conf.confirmation_id, "approved")
    store = QuarantineStore(str(tmp_path / "q"), key=KEY)
    f = tmp_path / "bad.bin"
    f.write_bytes(b"evil")
    ex = ResponseExecutor(mgr, quarantine=store)
    result = ex.execute(make_action("quarantine", target=str(f), requires_confirmation=True,
                                    confirmation_id=conf.confirmation_id))
    assert result.status == "executed"
    assert not f.exists() and len(store.list()) == 1


def test_executor_refuses_terminate():
    ex = ResponseExecutor(ConfirmationManager())
    result = ex.execute(make_action("terminate", target="1234", reversible=False))
    assert result.status == "refused"


def test_executor_blocks_network_with_firewall():
    calls = []

    class Result:
        returncode = 0
        stderr = ""

    def runner(argv, **kwargs):
        calls.append(argv)
        return Result()

    from core.response import FirewallController
    ex = ResponseExecutor(ConfirmationManager(),
                          firewall=FirewallController(runner=runner))
    result = ex.execute(make_action("block_network", target="10.0.0.1:445"))
    assert result.status == "executed"
    assert calls and calls[0][:4] == ["netsh", "advfirewall", "firewall", "add"]
    assert "remoteip=10.0.0.1" in calls[0] and "remoteport=445" in calls[0]


def test_executor_quarantine_failure_is_reported(tmp_path):
    mgr = ConfirmationManager()
    store = QuarantineStore(str(tmp_path / "q"), key=KEY)
    ex = ResponseExecutor(mgr, quarantine=store)
    result = ex.execute(make_action("quarantine", target=str(tmp_path / "missing.bin")))
    assert result.status == "failed" and "not found" in result.error


# ------------------------------------------------------------------ processes
@pytest.mark.skipif(sys.platform != "win32", reason="Windows process control")
def test_suspend_and_resume_real_process(tmp_path):
    flag = tmp_path / "progress.bin"
    code = ("import sys,time\n"
            "f=open(sys.argv[1],'ab')\n"
            "while True:\n"
            "    f.write(b'x'); f.flush(); time.sleep(0.02)\n")
    child = subprocess.Popen([sys.executable, "-c", code, str(flag)])
    try:
        time.sleep(0.4)
        size_before = flag.stat().st_size
        assert size_before > 0
        ctl = ProcessController()
        t0 = time.perf_counter()
        ctl.suspend(child.pid)
        suspend_ms = (time.perf_counter() - t0) * 1000
        time.sleep(0.2)
        frozen = flag.stat().st_size
        time.sleep(0.4)
        assert flag.stat().st_size == frozen, "process kept writing while suspended"
        t0 = time.perf_counter()
        ctl.resume(child.pid)
        resume_ms = (time.perf_counter() - t0) * 1000
        time.sleep(0.4)
        assert flag.stat().st_size > frozen, "process did not resume"
        assert suspend_ms < 5000 and resume_ms < 5000
    finally:
        child.kill()
        child.wait(timeout=5)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process control")
def test_suspend_unknown_pid_reports_error():
    with pytest.raises(ActionError):
        ProcessController().suspend(999_999_999)


def test_suspend_resolves_same_image_child(monkeypatch):
    """P0: a venv redirector stub leaves the real interpreter as a same-image child."""
    ctl = ProcessController()
    paused, resumed = [], []
    monkeypatch.setattr(ctl, "_process_table", lambda: {
        100: (1, "python.exe"),
        101: (100, "python.exe"),      # same image -> real interpreter
        102: (100, "other.exe"),       # different image -> must not be touched
    })
    monkeypatch.setattr(ctl, "_suspend_one", lambda pid: paused.append(pid))
    monkeypatch.setattr(ctl, "_resume_one", lambda pid: resumed.append(pid))
    assert ctl.suspend(100) == [100, 101]
    assert ctl.resume(100) == [100, 101]
    assert paused == [100, 101]
    assert resumed == [100, 101]


def test_executor_executes_after_confirmation_approved():
    """The real executor refuses while pending and runs once approved (P0 containment)."""
    class FakeProcesses:
        def __init__(self):
            self.calls = []

        def suspend(self, pid):
            self.calls.append(pid)

        def resume(self, pid):
            pass

    mgr = ConfirmationManager()
    ctl = FakeProcesses()
    ex = ResponseExecutor(mgr, processes=ctl)
    conf = mgr.request("action-1")
    action = make_action("suspend", target="123", requires_confirmation=True,
                         confirmation_id=conf.confirmation_id)
    assert ex.execute(action).status == "refused"
    mgr.resolve(conf.confirmation_id, "approved")
    assert ex.execute(action).status == "executed"
    assert ctl.calls == [123]
