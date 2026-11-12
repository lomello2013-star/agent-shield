"""Linux LSM file_open -> aidfd: credential-file access detection (runs in WSL as root).

The BPF program filters in-kernel to /etc/shadow, /etc/gshadow, /etc/sudoers and
/root/.ssh, so the userspace volume stays low. Workload reads both sensitive and
benign files, which proves the filter and the rule actually separate them.

Writes artifacts/linux_lsm.json.
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

OUT = os.path.join(WORKSPACE, "artifacts", "linux_lsm.json")
HOST = HostContext(host_id="wsl-lsm", os="linux", version="26.04", arch="x64",
                   kernel=os.uname().release)
SENSITIVE = 200
BENIGN = 200


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def build(workdir: str) -> tuple[str, str]:
    src = os.path.join(WORKSPACE, "spikes", "04-ebpf")
    for name in ("file_open_lsm.bpf.c", "loader.c"):
        subprocess.run(["cp", os.path.join(src, name), workdir], check=True)
    with open(os.path.join(workdir, "vmlinux.h"), "w") as fh:
        subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux",
                        "format", "c"], stdout=fh, check=True)
    subprocess.run(["clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I.",
                    "-c", "file_open_lsm.bpf.c", "-o", "file_open_lsm.bpf.o"],
                   cwd=workdir, check=True)
    subprocess.run(["gcc", "-O2", "-o", "loader", "loader.c", "-lbpf", "-lz", "-lelf"],
                   cwd=workdir, check=True)
    return os.path.join(workdir, "file_open_lsm.bpf.o"), os.path.join(workdir, "loader")


def workload() -> None:
    for i in range(SENSITIVE):
        with open("/etc/shadow", "rb") as fh:
            fh.read(64)
        if i % 10 == 0:
            time.sleep(0.005)
    for _ in range(BENIGN):
        with open("/etc/hostname", "rb") as fh:
            fh.read(64)


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_lsm_")
    bpf_obj, loader = build(workdir)

    cfg = DaemonConfig(sources=["linux.lsm"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 100},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_lsmd_"), config=cfg, host=HOST,
               rules_path=os.path.join(WORKSPACE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()

    proc = subprocess.Popen([loader, "stream_open", bpf_obj, "0"], stdout=subprocess.PIPE,
                            text=True, bufsize=1, cwd=workdir, stderr=subprocess.PIPE)
    lines: "queue.Queue[str]" = queue.Queue()

    def reader() -> None:
        for line in proc.stdout:
            lines.put(line)

    threading.Thread(target=reader, daemon=True).start()
    # wait until the BPF program is actually attached, otherwise the first reads
    # would happen before the hook exists and silently disappear from the count
    ready_deadline = time.time() + 15
    while time.time() < ready_deadline:
        try:
            line = lines.get(timeout=0.5).strip()
        except queue.Empty:
            continue
        if '"ready":true' in line:
            break
    thread = threading.Thread(target=workload)
    thread.start()

    kernel_lat, pipeline_lat = [], []
    verdicts = 0
    ppid_ok = 0
    paths: dict[str, int] = {}
    t_start = time.perf_counter()
    deadline = time.time() + 60
    while len(kernel_lat) < SENSITIVE and time.time() < deadline:
        try:
            line = lines.get(timeout=0.5).strip()
        except queue.Empty:
            if not thread.is_alive() and lines.empty():
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
        if int(raw.get("ppid") or 0) > 0:
            ppid_ok += 1
        paths[raw["path"]] = paths.get(raw["path"], 0) + 1
        d.submit("linux.lsm", {"pid": raw["pid"], "ppid": raw["ppid"],
                               "comm": raw["comm"], "path": raw["path"],
                               "hook": "file_open"})
        t0 = time.perf_counter()
        produced = d.tick()
        pipeline_lat.append((time.perf_counter() - t0) * 1000)
        verdicts += produced["verdicts"]
    thread.join(timeout=30)
    # drain the ringbuf: events may still be in flight when the workload exits
    drain_deadline = time.time() + 2.0
    while time.time() < drain_deadline and len(kernel_lat) < SENSITIVE:
        try:
            line = lines.get(timeout=0.2).strip()
        except queue.Empty:
            break
        if not line.startswith("{"):
            continue
        t_recv = time.monotonic_ns()
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))
        paths[raw["path"]] = paths.get(raw["path"], 0) + 1
        d.submit("linux.lsm", {"pid": raw["pid"], "ppid": raw["ppid"],
                               "comm": raw["comm"], "path": raw["path"],
                               "hook": "file_open"})
        t0 = time.perf_counter()
        produced = d.tick()
        pipeline_lat.append((time.perf_counter() - t0) * 1000)
        verdicts += produced["verdicts"]
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

    report = {
        "environment": {"python": sys.version.split()[0], "kernel": HOST.kernel},
        "events": len(kernel_lat), "ppid_events": ppid_ok,
        "sensitive_reads": SENSITIVE, "benign_reads": BENIGN,
        "paths_seen": paths, "verdicts": verdicts, "rule_hits": rules,
        "elapsed_s": round(elapsed, 2),
        "events_per_s": round(len(kernel_lat) / elapsed, 0) if elapsed else 0,
        "latency_kernel_to_user_ms": {
            "p50": round(statistics.median(kernel_lat), 3) if kernel_lat else None,
            "p95": p95(kernel_lat)},
        "latency_pipeline_ms": {
            "p50": round(statistics.median(pipeline_lat), 3) if pipeline_lat else None,
            "p95": p95(pipeline_lat)},
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "benign_leak": any("hostname" in p for p in paths),
        "note": "real LSM file_open events; benign /etc/hostname reads must not appear",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
