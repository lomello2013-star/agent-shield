from core.clock import MonotonicClock


class FakeTime:
    def __init__(self):
        self.mono = 1000.0
        self.wall = 1_700_000_000.0

    def mono_fn(self):
        return self.mono

    def wall_fn(self):
        return self.wall


def test_no_jump_when_clocks_agree():
    ft = FakeTime()
    clk = MonotonicClock(jump_threshold_s=5.0, mono_fn=ft.mono_fn, wall_fn=ft.wall_fn)
    ft.mono += 10
    ft.wall += 10
    assert clk.detect_jump() is None


def test_forward_wall_jump_detected():
    ft = FakeTime()
    clk = MonotonicClock(jump_threshold_s=5.0, mono_fn=ft.mono_fn, wall_fn=ft.wall_fn)
    ft.mono += 1
    ft.wall += 60          # NTP/manual jump forward
    jump = clk.detect_jump()
    assert jump is not None
    assert round(jump.skew_s) == 59
    assert len(clk.jumps) == 1


def test_backward_wall_jump_detected():
    ft = FakeTime()
    clk = MonotonicClock(jump_threshold_s=5.0, mono_fn=ft.mono_fn, wall_fn=ft.wall_fn)
    ft.mono += 2
    ft.wall -= 30
    jump = clk.detect_jump()
    assert jump is not None and jump.skew_s < 0


def test_monotonic_ns_is_int_and_monotonic():
    ft = FakeTime()
    clk = MonotonicClock(mono_fn=ft.mono_fn, wall_fn=ft.wall_fn)
    first = clk.mono_ns()
    ft.mono += 1
    second = clk.mono_ns()
    assert isinstance(first, int) and second - first == 1_000_000_000
