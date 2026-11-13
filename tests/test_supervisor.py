import pytest

from core.supervisor import Handle, Supervisor, SupervisorConfig


class FakeHandle:
    def __init__(self, exit_code: int | None = None):
        self.exit_code = exit_code
        self.terminated = False

    def poll(self):
        return self.exit_code

    def terminate(self):
        self.terminated = True


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_no_restart_while_child_is_alive():
    clock = Clock()
    spawned = []

    def spawn():
        handle = FakeHandle(None)
        spawned.append(handle)
        return handle

    sup = Supervisor(spawn=spawn, now_fn=clock)
    sup.start()
    for _ in range(5):
        clock.t += 1
        sup.check()
    assert len(spawned) == 1
    assert sup.status()["restarts"] == 0


def test_restart_after_crash_with_growing_backoff():
    clock = Clock()
    spawned = []

    def spawn():
        handle = FakeHandle(1)          # dies immediately every time
        spawned.append(handle)
        return handle

    sup = Supervisor(spawn=spawn, now_fn=clock,
                     config=SupervisorConfig(max_restarts=3, window_s=1000,
                                             backoff_base_s=1.0, backoff_max_s=8.0))
    sup.start()
    delays = []
    for _ in range(3):
        clock.t += 1
        status = sup.check()
        delays.append(status["last_delay_s"])
    assert delays == [1.0, 2.0, 4.0]
    assert sup.status()["restarts"] == 3


def test_circuit_opens_after_max_restarts_in_window():
    clock = Clock()
    spawned = []

    def spawn():
        handle = FakeHandle(1)
        spawned.append(handle)
        return handle

    sup = Supervisor(spawn=spawn, now_fn=clock,
                     config=SupervisorConfig(max_restarts=2, window_s=1000))
    sup.start()
    for _ in range(4):
        clock.t += 1
        sup.check()
    assert sup.status()["circuit_open"] is True
    assert len(spawned) == 3          # initial + 2 restarts, then refusal


def test_window_expiry_allows_restarts_again():
    clock = Clock()

    def spawn():
        return FakeHandle(1)

    sup = Supervisor(spawn=spawn, now_fn=clock,
                     config=SupervisorConfig(max_restarts=1, window_s=10))
    sup.start()
    clock.t += 1
    sup.check()                      # first restart used
    clock.t += 100                   # window passed
    sup.check()                      # allowed again
    status = sup.status()
    assert status["circuit_open"] is False
    assert status["restarts"] == 2


def test_clean_exit_is_not_restarted():
    clock = Clock()

    def spawn():
        return FakeHandle(0)

    sup = Supervisor(spawn=spawn, now_fn=clock)
    sup.start()
    clock.t += 1
    sup.check()
    assert sup.status()["running"] is False
    assert sup.status()["restarts"] == 0


def test_healthy_run_resets_restart_budget():
    clock = Clock()
    calls = {"n": 0}

    def spawn():
        calls["n"] += 1
        # first child dies, the restart spawns a healthy one
        return FakeHandle(1 if calls["n"] == 1 else None)

    sup = Supervisor(spawn=spawn, now_fn=clock,
                     config=SupervisorConfig(max_restarts=2, window_s=1000,
                                             healthy_after_s=5))
    sup.start()
    clock.t += 1
    sup.check()                       # one restart recorded, second child is alive
    assert sup.status()["recent_restarts"] == 1
    clock.t += 10                     # alive longer than healthy_after_s
    sup.check()
    assert sup.status()["recent_restarts"] == 0


def test_stop_terminates_child():
    handle = FakeHandle(None)
    sup = Supervisor(spawn=lambda: handle)
    sup.start()
    sup.stop()
    assert handle.terminated is True
    assert sup.status()["running"] is False
