from core.watchdog import ExternalWatchdog, ProcessHandle, Supervisor


class FakeProc(ProcessHandle):
    def __init__(self, exit_code=None):
        self._code = exit_code
        self.terminated = False

    def poll(self):
        return self._code

    def terminate(self):
        self.terminated = True


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_crash_triggers_restart_and_latency_recorded():
    clock = FakeClock()
    spawned = []

    def spawn():
        proc = FakeProc(exit_code=1)      # dies immediately
        spawned.append(proc)
        return proc

    sup = Supervisor(spawn=spawn, now_fn=clock, sleep_fn=lambda _: None)
    sup.tick()                    # spawn #1
    assert sup.state == "running"
    sup.tick()                    # detects exit -> schedules restart
    assert sup.crashes == 1 and sup.state == "stopped"
    clock.t += 10                 # past backoff
    sup.tick()                    # spawn #2
    assert len(spawned) == 2 and sup.state == "running"
    assert sup.restart_latencies and sup.restart_latencies[0] == 0.0


def test_backoff_grows_with_repeated_crashes():
    clock = FakeClock()
    sup = Supervisor(spawn=lambda: FakeProc(exit_code=1), backoff=(0.0, 1.0, 2.0, 4.0),
                     max_failures=10, now_fn=clock, sleep_fn=lambda _: None)
    sup.tick()
    for _ in range(4):
        sup.tick()                 # detect crash, schedule
        clock.t += 10
        sup.tick()                 # restart
    assert sup.restart_latencies[:4] == [0.0, 1.0, 2.0, 4.0]


def test_circuit_breaker_opens_and_requires_operator_reset():
    clock = FakeClock()
    sup = Supervisor(spawn=lambda: FakeProc(exit_code=1), backoff=(0.0,),
                     max_failures=3, failure_window_s=1000, now_fn=clock,
                     sleep_fn=lambda _: None)
    sup.tick()
    for _ in range(5):
        sup.tick()
        clock.t += 1
        sup.tick()
    assert sup.state == "failed"
    assert sup.reset(operator=False) is False
    assert sup.state == "failed"
    assert sup.reset(operator=True) is True
    assert sup.state == "stopped"


def test_healthy_process_stays_running():
    sup = Supervisor(spawn=lambda: FakeProc(exit_code=None), now_fn=FakeClock(),
                     sleep_fn=lambda _: None)
    for _ in range(5):
        sup.tick()
    assert sup.state == "running" and sup.crashes == 0 and sup.starts == 1


def test_restart_delay_capped_by_max_restart_s():
    clock = FakeClock()
    sup = Supervisor(spawn=lambda: FakeProc(exit_code=1), backoff=(1000.0,),
                     max_failures=50, max_restart_s=30.0, now_fn=clock,
                     sleep_fn=lambda _: None)
    sup.tick()
    sup.tick()
    assert sup.restart_latencies[0] == 30.0


def test_external_watchdog_missing_stale_and_fresh(tmp_path):
    path = tmp_path / "hb" / "external.hb"
    clock = FakeClock()
    wd = ExternalWatchdog(str(path), timeout_s=120, now_fn=clock)
    assert wd.check()["healthy"] is False            # missing
    wd.touch()
    assert wd.check()["healthy"] is True
    clock.t += 500
    stale = wd.check()
    assert stale["healthy"] is False and "stale" in stale["reason"]


def test_external_watchdog_unreadable_heartbeat(tmp_path):
    clock = FakeClock()
    path = tmp_path / "hb.json"
    path.write_text("not-a-number", encoding="utf-8")
    wd = ExternalWatchdog(str(path), timeout_s=10, now_fn=clock)
    assert wd.check()["healthy"] is False


def test_run_until_drives_supervision_cycle():
    clock = FakeClock()
    sup = Supervisor(spawn=lambda: FakeProc(exit_code=None), now_fn=clock,
                     sleep_fn=lambda d: setattr(clock, "t", clock.t + d))
    stats = sup.run_until(0.2, step_s=0.05)
    assert stats["starts"] == 1 and stats["state"] == "running"
    assert stats["name"] == "aidfd"
