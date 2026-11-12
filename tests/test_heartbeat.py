import pytest

from core.heartbeat import HeartbeatMonitor


class FakeTime:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_monitor(**kwargs):
    ft = FakeTime()
    incidents = []
    mon = HeartbeatMonitor(now_fn=ft, on_incident=incidents.append, **kwargs)
    return mon, ft, incidents


def test_beat_keeps_source_healthy():
    mon, ft, incidents = make_monitor(timeout_s=60)
    mon.register("win.etw.ti")
    ft.now += 10
    mon.beat("win.etw.ti", seq=1)
    assert mon.check() == []
    assert incidents == []
    assert mon.health()["win.etw.ti"]["healthy"] is True


def test_degraded_warning_then_escalation_keeps_r2_margin():
    """F04: warm at 50 % of the contract, incident at 75 % — R2 keeps a 25 % margin."""
    mon, ft, incidents = make_monitor(timeout_s=60)
    mon.register("linux.ebpf")
    ft.now += 30.1
    assert mon.check() == []                       # no incident yet
    assert [w.kind for w in mon.warnings] == ["degraded"]
    assert mon.health()["linux.ebpf"]["degraded"] is True

    ft.now += 15.0                                 # 45.1 s of silence
    opened = mon.check()
    assert len(opened) == 1
    assert opened[0].kind == "stalled"             # early, inside the 60 s contract
    assert 45 <= opened[0].silent_for_s < 60

    ft.now += 20                                   # 65 s: no duplicate, no kind change
    assert mon.check() == []
    assert len(incidents) == 1


def test_heartbeat_clears_degraded_state():
    mon, ft, _ = make_monitor(timeout_s=60)
    mon.register("win.etw.ti")
    ft.now += 31
    mon.check()
    assert mon.health()["win.etw.ti"]["degraded"] is True
    mon.beat("win.etw.ti", seq=2)
    assert mon.health()["win.etw.ti"]["degraded"] is False
    assert mon.health()["win.etw.ti"]["healthy"] is True


def test_silent_kind_after_hard_timeout():
    mon, ft, _ = make_monitor(timeout_s=60, escalate_s=60)
    mon.register("linux.ebpf")
    ft.now += 60.1
    opened = mon.check()
    assert len(opened) == 1 and opened[0].kind == "silent"


def test_beat_clears_incident_and_allows_redetection():
    mon, ft, incidents = make_monitor(timeout_s=10)
    mon.register("auditd")
    ft.now += 20
    mon.check()
    mon.beat("auditd")
    assert mon.health()["auditd"]["incident_open"] is False
    ft.now += 20
    assert len(mon.check()) == 1
    assert len(incidents) == 2


def test_out_of_order_heartbeat_does_not_extend_liveness():
    mon, ft, _ = make_monitor(timeout_s=10)
    mon.register("src")
    mon.beat("src", seq=5)
    ft.now += 10
    mon.beat("src", seq=4)             # stale seq: ignored
    ft.now += 1
    assert len(mon.check()) == 1


def test_probe_failure_raises_incident():
    mon, ft, incidents = make_monitor(timeout_s=60)
    mon.register("etw", probe=lambda: False)
    assert mon.probe("etw") is False
    assert incidents and incidents[0].kind == "probe_failed"


def test_probe_exception_counts_as_failure():
    def boom():
        raise RuntimeError("provider gone")
    mon, ft, incidents = make_monitor(timeout_s=60)
    mon.register("fanotify", probe=boom)
    assert mon.probe("fanotify") is False
    assert incidents[0].kind == "probe_failed"


def test_probe_success_and_missing_probe():
    mon, _, _ = make_monitor(timeout_s=60)
    mon.register("wfp", probe=lambda: True)
    assert mon.probe("wfp") is True
    mon.register("other")
    with pytest.raises(KeyError):
        mon.probe("other")


def test_unknown_source_rejected():
    mon, _, _ = make_monitor()
    with pytest.raises(KeyError):
        mon.beat("ghost")
    with pytest.raises(ValueError):
        mon.register("")


def test_all_healthy_reflects_state():
    mon, ft, _ = make_monitor(timeout_s=5)
    mon.register("a"); mon.register("b")
    assert mon.all_healthy()
    ft.now += 10
    mon.check()
    assert not mon.all_healthy()
