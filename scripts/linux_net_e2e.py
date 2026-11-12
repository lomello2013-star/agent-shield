"""Linux L4 detection: cgroup/connect4 observer -> aidfd -> C2-port verdicts (WSL root).

The BPF program returns 1 (allow) and only emits events; the rule decides. The
workload mixes C2-like port 4444 (should alert) with benign 8080 (event, no verdict),
which proves the separation instead of just counting events.

Writes artifacts/linux_net.json.
"""

from __future__ import annotations

import json
import os
import queue
import socket
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

OUT = os.path.join(WORKSPACE, "artifacts", "linux_net.json")
HOST = HostContext(host_id="wsl-net", os="linux", version="26.04", arch="x64",
                   kernel=os.uname().release)
CGROUP = "/sys/fs/cgroup/aidf"
C2_PORT = 4444
BENIGN_PORT = 8080
C2_CONNECTS = 200
BENIGN_CONNECTS = 200


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def build(workdir: str) -> tuple[str, str]:
    src = os.path.join(WORKSPACE, "spikes", "04-ebpf")
    for name in ("net_connect_event.bpf.c", "loader.c"):
        subprocess.run(["cp", os.path.join(src, name), workdir], check=True)
    with open(os.path.join(workdir, "vmlinux.h"), "w") as fh:
        subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux",
                        "format", "c"], stdout=fh, check=True)
    subprocess.run(["clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I.",
                    "-c", "net_connect_event.bpf.c", "-o", "net_connect_event.bpf.o"],
                   cwd=workdir, check=True)
    subprocess.run(["gcc", "-O2", "-o", "loader", "loader.c", "-lbpf", "-lz", "-lelf"],
                   cwd=workdir, check=True)
    return os.path.join(workdir, "net_connect_event.bpf.o"), os.path.join(workdir, "loader")


def listener(port: int, stop: threading.Event) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    srv.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
            conn.close()
        except socket.timeout:
            continue
    srv.close()


def connect(port: int, count: int) -> None:
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect(("127.0.0.1", port))
        finally:
            s.close()


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_net_")
    bpf_obj, loader = build(workdir)

    os.makedirs(CGROUP, exist_ok=True)
    with open(os.path.join(CGROUP, "cgroup.procs"), "w") as fh:
        fh.write(str(os.getpid()))

    cfg = DaemonConfig(sources=["linux.net"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 100},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_netd_"), config=cfg, host=HOST,
               rules_path=os.path.join(WORKSPACE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()

    proc = subprocess.Popen([loader, "stream_net", bpf_obj, CGROUP, "0"],
                            stdout=subprocess.PIPE, text=True, bufsize=1,
                            cwd=workdir, stderr=subprocess.PIPE)
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

    stop = threading.Event()
    for port in (C2_PORT, BENIGN_PORT):
        threading.Thread(target=listener, args=(port, stop), daemon=True).start()
    time.sleep(0.3)

    kernel_lat, pipeline_lat = [], []
    verdicts = 0
    ppid_ok = 0
    ports_seen: dict[int, int] = {}
    t_start = time.perf_counter()
    worker = threading.Thread(target=lambda: (connect(C2_PORT, C2_CONNECTS),
                                              connect(BENIGN_PORT, BENIGN_CONNECTS)))
    worker.start()
    deadline = time.time() + 60
    expected = C2_CONNECTS + BENIGN_CONNECTS
    while len(kernel_lat) < expected and time.time() < deadline:
        try:
            line = lines.get(timeout=0.5).strip()
        except queue.Empty:
            if not worker.is_alive() and lines.empty():
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
        ports_seen[raw["dport"]] = ports_seen.get(raw["dport"], 0) + 1
        d.submit("linux.net", {"pid": raw["pid"], "ppid": raw.get("ppid"),
                               "comm": raw["comm"],
                               "daddr": raw["daddr"], "dport": raw["dport"]})
        t0 = time.perf_counter()
        produced = d.tick()
        pipeline_lat.append((time.perf_counter() - t0) * 1000)
        verdicts += produced["verdicts"]
    worker.join(timeout=30)
    stop.set()
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

    # Best-effort cleanup: moving a live process out of a delegated cgroup can be
    # refused (EBUSY); that must not lose the measurement.
    try:
        with open("/sys/fs/cgroup/cgroup.procs", "w") as fh:
            fh.write(str(os.getpid()))
    except OSError:
        pass
    try:
        os.rmdir(CGROUP)
    except OSError:
        pass

    report = {
        "environment": {"python": sys.version.split()[0], "kernel": HOST.kernel},
        "c2_connects": C2_CONNECTS, "benign_connects": BENIGN_CONNECTS,
        "events": len(kernel_lat), "ppid_events": ppid_ok,
        "ports_seen": ports_seen,
        "verdicts": verdicts, "rule_hits": rules,
        "elapsed_s": round(elapsed, 2),
        "latency_kernel_to_user_ms": {
            "p50": round(statistics.median(kernel_lat), 3) if kernel_lat else None,
            "p95": p95(kernel_lat)},
        "latency_pipeline_ms": {
            "p50": round(statistics.median(pipeline_lat), 3) if pipeline_lat else None,
            "p95": p95(pipeline_lat)},
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "benign_verdicts": verdicts - rules.get("LINUX-C2-PORT-105", 0),
        "note": "cgroup/connect4 observer; port 4444 alerts, port 8080 is only an event",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
