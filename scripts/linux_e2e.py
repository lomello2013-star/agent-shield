"""Linux end-to-end: real eBPF exec events -> aidfd -> verdicts (runs inside WSL as root).

Measures:
  * kernel->userspace latency (BPF ktime at exec vs reader receive, same monotonic clock);
  * userspace pipeline latency (receive -> verdict);
  * throughput, event loss, ledger integrity, rule hits on real processes.

The script compiles the BPF object itself (clang is present in the dev WSL image) and
streams JSON lines from the loader. Nothing here is synthesised: every event is a real
`sched_process_exec` from the kernel.
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time

WORKSPACE = os.environ.get("AIDF_WORKSPACE", "/mnt/d/ИИ защитник Вектор-защитник")
sys.path.insert(0, WORKSPACE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

EBPF_DIR = os.path.join(WORKSPACE, "spikes", "04-ebpf")
OUT = os.path.join(WORKSPACE, "artifacts", "linux_e2e.json")
HOST = HostContext(host_id="wsl-linux", os="linux", version="26.04", arch="x64",
                   kernel=os.uname().release)


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def build(workdir: str) -> tuple[str, str]:
    subprocess.run(["cp", os.path.join(EBPF_DIR, "exec_path.bpf.c"), workdir], check=True)
    subprocess.run(["cp", os.path.join(EBPF_DIR, "loader.c"), workdir], check=True)
    # vmlinux.h is generated from the running kernel's BTF (CO-RE, no kernel headers needed)
    with open(os.path.join(workdir, "vmlinux.h"), "w") as fh:
        subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux",
                        "format", "c"], stdout=fh, check=True)
    subprocess.run(["clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I.",
                    "-c", "exec_path.bpf.c", "-o", "exec_path.bpf.o"],
                   cwd=workdir, check=True)
    subprocess.run(["gcc", "-O2", "-o", "loader", "loader.c", "-lbpf", "-lz", "-lelf"],
                   cwd=workdir, check=True)
    return os.path.join(workdir, "exec_path.bpf.o"), os.path.join(workdir, "loader")


def workload(binary: str, count: int) -> None:
    """Exec a /tmp copy (should hit LINUX-EXEC-TMP-101) and a benign binary."""
    for i in range(count):
        subprocess.run([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if i % 2 == 0:
            subprocess.run(["/bin/true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_linux_")
    bpf_obj, loader = build(workdir)

    tmp_binary = "/tmp/aidf_probe_exec"
    with open("/bin/true", "rb") as src, open(tmp_binary, "wb") as dst:
        dst.write(src.read())
    os.chmod(tmp_binary, 0o755)

    cfg = DaemonConfig(sources=["linux.ebpf"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 50,
                                   "min_confidence": 0.5},
                       queue={"capacity": 5000})
    daemon_root = tempfile.mkdtemp(prefix="aidf_daemon_")
    d = Daemon(daemon_root, config=cfg, host=HOST,
               rules_path=os.path.join(WORKSPACE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()

    n_events = 200
    proc = subprocess.Popen([loader, "stream", bpf_obj, "0"],      # 0 = until terminated
                            stdout=subprocess.PIPE, text=True, bufsize=1,
                            cwd=workdir, stderr=subprocess.PIPE)

    kernel_lat, pipeline_lat = [], []
    verdicts = 0
    ppid_ok = 0
    rule_hits: dict[str, int] = {}
    import queue
    lines: "queue.Queue[str]" = queue.Queue()

    def reader() -> None:
        for line in proc.stdout:
            lines.put(line)

    threading.Thread(target=reader, daemon=True).start()
    thread = threading.Thread(target=workload, args=(tmp_binary, n_events))
    thread.start()

    t_start = time.perf_counter()
    deadline = time.time() + 90
    while len(kernel_lat) < n_events and time.time() < deadline:
        try:
            line = lines.get(timeout=0.5).strip()
        except queue.Empty:
            continue
        if not line or not line.startswith("{"):
            continue
        t_recv = time.monotonic_ns()
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))     # ms
        if int(raw.get("ppid") or 0) > 0:
            ppid_ok += 1
        d.submit("linux.ebpf", {
            "pid": raw["pid"], "ppid": raw["ppid"], "comm": raw["comm"],
            "exe": raw["filename"], "syscall": "execve",
        })
        t0 = time.perf_counter()
        produced = d.tick()
        pipeline_lat.append((time.perf_counter() - t0) * 1000)
        verdicts += produced["verdicts"]
        rule_hits = dict(d.engine.counts())
    thread.join(timeout=30)
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        pass

    # drain what is still queued
    while d.pipeline.ingest.backlog_events() > 0:
        produced = d.tick()
        verdicts += produced["verdicts"]
    health = d.health()
    elapsed = time.perf_counter() - t_start
    d.stop()
    os.remove(tmp_binary)

    report = {
        "environment": {"python": sys.version.split()[0], "kernel": HOST.kernel},
        "events": len(kernel_lat), "ppid_events": ppid_ok,
        "elapsed_s": round(elapsed, 2),
        "events_per_s": round(len(kernel_lat) / elapsed, 0) if elapsed else 0,
        "verdicts": verdicts,
        "rule_hits": rule_hits,
        "latency_kernel_to_user_ms": {
            "p50": round(statistics.median(kernel_lat), 3) if kernel_lat else None,
            "p95": p95(kernel_lat), "max": round(max(kernel_lat), 3) if kernel_lat else None},
        "latency_pipeline_ms": {
            "p50": round(statistics.median(pipeline_lat), 3) if pipeline_lat else None,
            "p95": p95(pipeline_lat)},
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "real sched_process_exec events; /tmp/aidf_probe_exec triggers LINUX-EXEC-TMP-101",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
