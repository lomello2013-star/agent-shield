"""Soak run for the `aidfd` skeleton: continuous load + scheduled faults.

Default duration is 180 s (a full 7-day soak belongs to the release stage, not to
a single agent session; the harness is the same, only the duration differs).

Writes artifacts/soak_report.json.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import faulthandler
import json
import os
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.daemon import Daemon, DaemonConfig
from core.normalize import HostContext

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "artifacts", "soak_report.json")
DURATION_S = float(os.environ.get("AIDF_SOAK_SECONDS", "180"))
RATE_PER_S = 200.0
HOST = HostContext(host_id="host-soak", os="windows", version="10.0.19045", arch="x64")


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def rss_mb() -> float:
    try:
        import psutil
        return round(psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024), 1)
    except Exception:
        pass
    try:
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        ctypes.windll.psapi.GetProcessMemoryInfo(
            ctypes.windll.kernel32.GetCurrentProcess(),
            ctypes.byref(counters), counters.cb)
        return round(counters.WorkingSetSize / (1024 * 1024), 1)
    except Exception:
        return -1.0


def event(i: int) -> dict:
    lsass = i % 250 == 0
    return {"process_id": 1000 + (i % 5000), "parent_id": 4,
            "process_name": r"C:\Temp\dropper.exe" if lsass else r"C:\Windows\System32\cmd.exe",
            "target": r"C:\Windows\System32\lsass.exe" if lsass else r"C:\Users\public\f.txt",
            "category": "process.access" if lsass else "file.write",
            "action": "open_process" if lsass else "write"}


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def rss_last_60s_growth(samples: list[dict]) -> float | None:
    """RSS growth over the last 60 s of samples (percent) — the leak indicator."""
    recent = [s for s in samples if s["t"] >= samples[-1]["t"] - 60] if samples else []
    if len(recent) < 2:
        return None
    first, last = recent[0]["rss_mb"], recent[-1]["rss_mb"]
    if first <= 0:
        return None
    return round(100 * (last - first) / first, 2)


def rss_plateau(samples: list[dict], window_s: float = 60.0,
                tolerance_mb: float = 1.0) -> bool | None:
    """True when RSS stopped moving at the end of the run (warm-up vs leak)."""
    recent = [s for s in samples if s["t"] >= samples[-1]["t"] - window_s] if samples else []
    if len(recent) < 2:
        return None
    return (max(s["rss_mb"] for s in recent) - min(s["rss_mb"] for s in recent)) <= tolerance_mb


def install_native_probe() -> None:
    """Opt-in: resolve a faulting address to its module (see scripts/native_crash_probe.py)."""
    if os.environ.get("AIDF_NATIVE_PROBE") != "1":
        return
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import native_crash_probe
    native_crash_probe.install()


def install_stack_dump() -> None:
    """If the run stalls, keep writing stack traces so the hang is diagnosable."""
    path = os.path.join(os.path.dirname(REPORT), "_stdout", "soak_stacks.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fh = open(path, "a", encoding="utf-8", buffering=1)
    # enable() installs the fault handler: an access violation then prints the Python
    # stack at the moment of the crash, not only on timeouts.
    faulthandler.enable(file=fh, all_threads=True)
    faulthandler.dump_traceback_later(120, repeat=True, file=fh)
    return None


def main() -> None:
    install_stack_dump()
    install_native_probe()
    tmp = tempfile.mkdtemp(prefix="aidf_soak_")
    cfg = DaemonConfig(sources=["win.etw.ti"],
                       thresholds={"heartbeat_timeout_s": 2.0, "alert_budget": 20,
                                   "min_confidence": 0.5},
                       queue={"capacity": 5000})
    d = Daemon(os.path.join(tmp, "daemon"), config=cfg, host=HOST,
               serve_http=False, log_fsync_every=64)
    if os.environ.get("AIDF_NO_MANIFEST") == "1":
        # diagnostic: health() no longer re-hashes the whole data directory
        d.manifest.verify = lambda *a, **k: {"ok": True, "files": {}, "checked": 0}
    d.start()
    stop = threading.Event()
    fed = [0]
    feed_paused = threading.Event()
    errors: list[str] = []

    def feeder() -> None:
        i = 0
        next_t = time.perf_counter()
        while not stop.is_set():
            if feed_paused.is_set():
                time.sleep(0.05)
                continue
            d.submit("win.etw.ti", event(i))
            fed[0] += 1
            i += 1
            next_t += 1.0 / RATE_PER_S
            delay = next_t - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            else:
                next_t = time.perf_counter()

    health_lat, samples = [], []
    sample_stop = threading.Event()

    def sampler() -> None:
        if os.environ.get("AIDF_NO_SAMPLER") == "1":
            return          # diagnostic mode: no health()/rss from this thread
        while not sample_stop.is_set():
            t0 = time.perf_counter()
            h = d.health()
            health_lat.append((time.perf_counter() - t0) * 1000)
            samples.append({"t": round(time.monotonic() - start, 1),
                            "status": h["status"], "rss_mb": rss_mb(),
                            "verdicts": h["verdicts"], "lost": h["ingest"]["lost"],
                            "backlog": h["ingest"]["backlog"]})
            # progressive output: a hung run still leaves evidence of where it stopped
            if len(samples) % 5 == 0:
                partial = {"partial": True, "t_s": samples[-1]["t"],
                           "status": samples[-1]["status"], "rss_mb": samples[-1]["rss_mb"],
                           "events_fed": fed[0], "lost": samples[-1]["lost"],
                           "backlog": samples[-1]["backlog"]}
                try:
                    with open(os.path.join(os.path.dirname(REPORT),
                                           "soak_partial.json"), "w",
                              encoding="utf-8") as fh:
                        json.dump(partial, fh)
                except OSError:
                    pass
                print(f"[soak] t={samples[-1]['t']}s fed={fed[0]} "
                      f"rss={samples[-1]['rss_mb']} backlog={samples[-1]['backlog']}",
                      flush=True)
            time.sleep(2.0)

    start = time.monotonic()
    ft = threading.Thread(target=feeder, daemon=True)
    st = threading.Thread(target=sampler, daemon=True)
    ft.start(); st.start()

    tick_lat = []
    faults: dict[str, object] = {}
    rss_start = rss_mb()
    while True:
        elapsed = time.monotonic() - start
        if elapsed >= DURATION_S:
            break
        t0 = time.perf_counter()
        d.tick()
        tick_lat.append((time.perf_counter() - t0) * 1000)

        # fault 1: silence the source for 5 s (R2)
        if 30 <= elapsed < 30.02 and "source_death" not in faults:
            feed_paused.set()
            t_pause = time.perf_counter()
            detected = None
            while time.perf_counter() - t_pause < 8:
                d.tick()
                if d.health()["status"] == "degraded":
                    detected = time.perf_counter() - t_pause
                    break
                time.sleep(0.02)
            faults["source_death"] = {"detected": detected is not None,
                                      "detection_s": round(detected, 3) if detected else None}
            feed_paused.clear()

        # fault 2: bad config -> safe mode (LKG must survive)
        if 60 <= elapsed < 60.02 and "bad_config" not in faults:
            good = d.safe_mode.load_lkg()
            bad = DaemonConfig(thresholds={"alert_budget": -3}).as_payload()
            res = d.safe_mode.apply(bad, dry_run=False)
            faults["bad_config"] = {"accepted": res.accepted, "safe_mode": d.safe_mode.is_safe,
                                    "lkg_unchanged": d.safe_mode.load_lkg() == good}

        # fault 3: burst while the consumer is paused -> spill, no loss
        if 90 <= elapsed < 90.02 and "storm" not in faults:
            before = d.pipeline.ingest.stats()
            for i in range(3000):
                d.submit("win.etw.ti", event(100000 + i))
            time.sleep(1.0)
            mid = d.pipeline.ingest.stats()
            while d.pipeline.ingest.backlog_events() > 0:
                d.tick()
            after = d.pipeline.ingest.stats()
            faults["storm"] = {"submitted": 3000, "spilled": mid["spilled_pending"],
                               "lost": after["lost"], "ledger_ok": d.pipeline.ingest.ledger_ok()}

        # fault 4: clock jump
        if 120 <= elapsed < 120.02 and "clock_jump" not in faults:
            class FakeWall:
                def __init__(self):
                    self.t = time.time()
                def __call__(self):
                    return self.t
            fake = FakeWall()
            d.clock._wall_fn = fake
            d.clock._last_wall = fake.t
            fake.t += 7200
            d.tick()
            d.log.flush()          # batched writer: flush before reading the file
            # context manager on purpose: an unclosed handle leaks on long runs
            with open(d.log.path, encoding="utf-8") as fh:
                jumps = sum(1 for line in fh if '"clock_jump"' in line)
            faults["clock_jump"] = {"logged": jumps > 0}

        time.sleep(0.02)

    stop.set(); sample_stop.set()
    ft.join(timeout=5); st.join(timeout=5)
    health = d.health()
    rss_end = rss_mb()
    t0 = time.perf_counter()
    d.stop()
    shutdown_ms = (time.perf_counter() - t0) * 1000

    report = {
        "environment": {"python": sys.version.split()[0], "duration_s": DURATION_S,
                        "rate_per_s": RATE_PER_S},
        "load": {"events_fed": fed[0], "ticks": len(tick_lat),
                 "tick_ms_p50": round(statistics.median(tick_lat), 3),
                 "tick_ms_p95": p95(tick_lat), "tick_ms_max": round(max(tick_lat), 3)},
        "health": {"http_calls": len(health_lat), "ms_p50": round(statistics.median(health_lat), 3),
                   "ms_p95": p95(health_lat)},
        "memory": {"rss_start_mb": rss_start, "rss_end_mb": rss_end,
                   "growth_pct": round(100 * (rss_end - rss_start) / max(1.0, rss_start), 2)},
        "faults": faults,
        "final": {"lost": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
                  "verdicts": health["verdicts"], "alerts": health["alerts"],
                  "containments": health["containments"],
                  "audit_chain_ok": health["audit_chain_ok"],
                  "integrity_ok": health["integrity_ok"],
                  "shutdown_ms": round(shutdown_ms, 3)},
        "samples_tail": samples[-5:],
        "samples": samples[::10],
        "rss_growth_last_60s_pct": rss_last_60s_growth(samples),
        "rss_plateau": rss_plateau(samples),
        "errors": errors,
    }
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

