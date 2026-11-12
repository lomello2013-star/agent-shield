"""Linux memory-write detection: sys_enter_process_vm_writev -> aidfd -> verdict (WSL root).

The helper forks a child and writes into its memory N times; events are real kernel
syscall tracepoints. A control phase runs benign processes and must produce zero
memory events. Writes artifacts/linux_mem.json.
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

WORKSPACE = os.environ.get("AIDF_WORKSPACE", "/mnt/d/Р ВР В Р В·Р В°РЎвЂ°Р С‘РЎвЂљР Р…Р С‘Р С” Р вЂ™Р ВµР С”РЎвЂљР С•РЎР‚-Р В·Р В°РЎвЂ°Р С‘РЎвЂљР Р…Р С‘Р С”")
sys.path.insert(0, WORKSPACE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

OUT = os.path.join(WORKSPACE, "artifacts", "linux_mem.json")
HOST = HostContext(host_id="wsl-mem", os="linux", version="26.04", arch="x64",
                   kernel=os.uname().release)
WRITES = 100


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def build(workdir: str) -> tuple[str, str, str]:
    src = os.path.join(WORKSPACE, "spikes", "04-ebpf")
    for name in ("mem_write.bpf.c", "loader.c"):
        subprocess.run(["cp", os.path.join(src, name), workdir], check=True)
    with open(os.path.join(workdir, "vmlinux.h"), "w") as fh:
        subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux",
                        "format", "c"], stdout=fh, check=True)
    subprocess.run(["clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I.",
                    "-c", "mem_write.bpf.c", "-o", "mem_write.bpf.o"],
                   cwd=workdir, check=True)
    subprocess.run(["gcc", "-O2", "-o", "loader", "loader.c", "-lbpf", "-lz", "-lelf"],
                   cwd=workdir, check=True)
    subprocess.run(["gcc", "-O2", "-o", "memwrite",
                    os.path.join(src, "memwrite_helper.c")],
                   cwd=workdir, check=True)
    return (os.path.join(workdir, "mem_write.bpf.o"), os.path.join(workdir, "loader"),
            os.path.join(workdir, "memwrite"))


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_mem_")
    bpf_obj, loader, helper = build(workdir)

    cfg = DaemonConfig(sources=["linux.memory"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 50},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_memd_"), config=cfg, host=HOST,
               rules_path=os.path.join(WORKSPACE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()

    proc = subprocess.Popen([loader, "stream_mem", bpf_obj, "0"], stdout=subprocess.PIPE,
                            text=True, bufsize=1, cwd=workdir, stderr=subprocess.PIPE)
    lines: "queue.Queue[str]" = queue.Queue()

    def reader() -> None:
        for line in proc.stdout:
            lines.put(line)

    threading.Thread(target=reader, daemon=True).start()
    ready_deadline = time.time() + 15
    while time.time() < ready_deadline:
        try:
            if '"ready":true' in lines.get(timeout=0.5):
                break
        except queue.Empty:
            continue

    events, kernel_lat, pipeline_lat = [], [], []
    verdicts = 0
    rule_hits: dict[str, int] = {}

    def consume(deadline: float) -> None:
        nonlocal verdicts
        while time.time() < deadline:
            try:
                line = lines.get(timeout=0.2).strip()
            except queue.Empty:
                continue
            if not line.startswith("{"):
                continue
            t_recv = time.monotonic_ns()
            raw = json.loads(line)
            if "target" not in raw:
                continue
            events.append(raw)
            kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))
            d.submit("linux.memory", {"pid": raw["pid"], "target": raw["target"],
                                      "comm": raw["comm"], "bytes": raw["bytes"]})
            t0 = time.perf_counter()
            produced = d.tick()
            pipeline_lat.append((time.perf_counter() - t0) * 1000)
            verdicts += produced["verdicts"]

    # control: benign processes, no process_vm_writev expected
    t_control = time.time()
    for _ in range(20):
        subprocess.run(["/bin/true"], stdout=subprocess.DEVNULL)
    consume(time.time() + 1.0)
    control_events = len(events)

    # attack-ish workload: real cross-process writes, consumed concurrently so the
    # latency measured is kernel->userspace, not "how long the helper ran"
    helper_proc = subprocess.Popen([helper, str(WRITES)], cwd=workdir,
                                   stdout=subprocess.PIPE, text=True)
    consume(time.time() + 10.0)
    helper_out = helper_proc.communicate(timeout=20)[0].strip()
    consume(time.time() + 0.5)
    rule_hits = dict(d.engine.counts())
    while d.pipeline.ingest.backlog_events() > 0:
        produced = d.tick()
        verdicts += produced["verdicts"]
    health = d.health()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    d.stop()

    report = {
        "environment": {"python": sys.version.split()[0], "kernel": HOST.kernel},
        "helper_writes_reported": helper_out,
        "control_events": control_events,
        "events": len(events),
        "verdicts": verdicts,
        "rule_hits": rule_hits,
        "latency_kernel_to_user_ms": {
            "p50": round(statistics.median(kernel_lat), 3) if kernel_lat else None,
            "p95": p95(kernel_lat)},
        "latency_pipeline_ms": {
            "p50": round(statistics.median(pipeline_lat), 3) if pipeline_lat else None,
            "p95": p95(pipeline_lat)},
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "real sys_enter_process_vm_writev events; every event should alert",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()



