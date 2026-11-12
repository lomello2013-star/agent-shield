"""Linux load run: 10k real exec events through the pipeline (runs in WSL as root).

Measures throughput, loss/ledger, backlog behaviour and kernel->verdict latency
under sustained load (not a smoke run). Writes artifacts/linux_load.json.
"""

from __future__ import annotations

import json
import os
import queue
import statistics
import subprocess
import sys
import tempfile
import threading
import time

WORKSPACE = os.environ.get("AIDF_WORKSPACE", "/mnt/d/ИИ защитник Вектор-защитник")
sys.path.insert(0, WORKSPACE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402
from linux_e2e import build  # noqa: E402

OUT = os.path.join(WORKSPACE, "artifacts", "linux_load.json")
HOST = HostContext(host_id="wsl-load", os="linux", version="26.04", arch="x64",
                   kernel=os.uname().release)
TARGET = int(os.environ.get("AIDF_LOAD_EVENTS", "10000"))


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_load_")
    bpf_obj, loader = build(workdir)

    probe = "/tmp/aidf_load_exec"
    with open("/bin/true", "rb") as src, open(probe, "wb") as dst:
        dst.write(src.read())
    os.chmod(probe, 0o755)

    cfg = DaemonConfig(sources=["linux.ebpf"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 100},
                       queue={"capacity": 20000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_ld_"), config=cfg, host=HOST,
               rules_path=os.path.join(WORKSPACE, "rules", "base.json"),
               log_fsync_every=256)
    d.start()

    proc = subprocess.Popen([loader, "stream", bpf_obj, "0"], stdout=subprocess.PIPE,
                            text=True, bufsize=1, cwd=workdir, stderr=subprocess.PIPE)
    lines: "queue.Queue[str]" = queue.Queue()

    def reader() -> None:
        for line in proc.stdout:
            lines.put(line)

    threading.Thread(target=reader, daemon=True).start()

    half = TARGET // 2
    script = (f"for i in $(seq 1 {half}); do {probe}; /bin/true; done")
    workload = threading.Thread(target=subprocess.run, args=(["bash", "-c", script],),
                                kwargs={"stdout": subprocess.DEVNULL,
                                        "stderr": subprocess.DEVNULL})
    workload.start()

    kernel_lat, pipeline_lat = [], []
    verdicts = 0
    backlog_max = 0
    t_start = time.perf_counter()
    deadline = time.time() + 240
    while len(kernel_lat) < TARGET and time.time() < deadline:
        try:
            line = lines.get(timeout=0.5).strip()
        except queue.Empty:
            if not workload.is_alive() and lines.empty():
                break
            continue
        if not line.startswith("{"):
            continue
        t_recv = time.monotonic_ns()
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))
        d.submit("linux.ebpf", {"pid": raw["pid"], "ppid": raw["ppid"],
                                "comm": raw["comm"], "exe": raw["filename"],
                                "syscall": "execve"})
        if len(kernel_lat) % 50 == 0:
            t0 = time.perf_counter()
            produced = d.tick()
            pipeline_lat.append((time.perf_counter() - t0) * 1000)
            verdicts += produced["verdicts"]
            backlog_max = max(backlog_max, d.pipeline.ingest.backlog_events())
    workload.join(timeout=120)
    while d.pipeline.ingest.backlog_events() > 0:
        produced = d.tick()
        verdicts += produced["verdicts"]
    elapsed = time.perf_counter() - t_start
    health = d.health()
    rules = d.engine.counts()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    d.stop()
    os.remove(probe)

    report = {
        "environment": {"python": sys.version.split()[0], "kernel": HOST.kernel,
                        "target": TARGET},
        "events": len(kernel_lat), "elapsed_s": round(elapsed, 2),
        "events_per_s": round(len(kernel_lat) / elapsed, 0) if elapsed else 0,
        "verdicts": verdicts, "rule_hits": rules, "backlog_max": backlog_max,
        "latency_kernel_to_user_ms": {
            "p50": round(statistics.median(kernel_lat), 3) if kernel_lat else None,
            "p95": p95(kernel_lat),
            "max": round(max(kernel_lat), 3) if kernel_lat else None},
        "latency_pipeline_ms": {
            "p50": round(statistics.median(pipeline_lat), 3) if pipeline_lat else None,
            "p95": p95(pipeline_lat)},
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "real exec events under sustained load; every second exec comes from /tmp",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
