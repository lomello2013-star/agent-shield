"""Linux mprotect(PROT_EXEC) detection: JIT/injection primitive (WSL root).

Emits only when EXEC is newly added to an anonymous mapping (vm_flags lacked VM_EXEC),
so a browser/node JIT shows up as a candidate; the rule is medium severity for that
reason. Control phase (benign processes) must stay quiet.

Writes artifacts/linux_mprotect.json.
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

WORKSPACE = os.environ.get("AIDF_WORKSPACE", "/mnt/d/РР Р·Р°С‰РёС‚РЅРёРє Р’РµРєС‚РѕСЂ-Р·Р°С‰РёС‚РЅРёРє")
sys.path.insert(0, WORKSPACE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

OUT = os.path.join(WORKSPACE, "artifacts", "linux_mprotect.json")
HOST = HostContext(host_id="wsl-mprot", os="linux", version="26.04", arch="x64",
                   kernel=os.uname().release)
MAPS = 100


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def build(workdir: str) -> tuple[str, str, str]:
    src = os.path.join(WORKSPACE, "spikes", "04-ebpf")
    for name in ("mprotect_exec.bpf.c", "loader.c"):
        subprocess.run(["cp", os.path.join(src, name), workdir], check=True)
    with open(os.path.join(workdir, "vmlinux.h"), "w") as fh:
        subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux",
                        "format", "c"], stdout=fh, check=True)
    subprocess.run(["clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I.",
                    "-c", "mprotect_exec.bpf.c", "-o", "mprotect_exec.bpf.o"],
                   cwd=workdir, check=True)
    subprocess.run(["gcc", "-O2", "-o", "loader", "loader.c", "-lbpf", "-lz", "-lelf"],
                   cwd=workdir, check=True)
    subprocess.run(["gcc", "-O2", "-o", "mprotect_helper",
                    os.path.join(src, "mprotect_helper.c")], cwd=workdir, check=True)
    return (os.path.join(workdir, "mprotect_exec.bpf.o"), os.path.join(workdir, "loader"),
            os.path.join(workdir, "mprotect_helper"))


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_mprot_")
    bpf_obj, loader, helper = build(workdir)

    cfg = DaemonConfig(sources=["linux.mprotect"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 200},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_mpd_"), config=cfg, host=HOST,
               rules_path=os.path.join(WORKSPACE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()

    proc = subprocess.Popen([loader, "stream_mprotect", bpf_obj, "0"], stdout=subprocess.PIPE,
                            text=True, bufsize=1, cwd=workdir, stderr=subprocess.PIPE)
    lines: "queue.Queue[str]" = queue.Queue()

    def reader() -> None:
        for line in proc.stdout:
            lines.put(line)

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if '"ready":true' in lines.get(timeout=0.5):
                break
        except queue.Empty:
            continue

    events, kernel_lat, pipeline_lat = [], [], []
    verdicts = 0
    mine = 0
    from collections import Counter
    comms = Counter()

    def consume(deadline_ts: float) -> None:
        nonlocal verdicts, mine
        while time.time() < deadline_ts:
            try:
                line = lines.get(timeout=0.2).strip()
            except queue.Empty:
                continue
            if not line.startswith("{"):
                continue
            t_recv = time.monotonic_ns()
            raw = json.loads(line)
            if "anon" not in raw:
                continue
            events.append(raw)
            if raw["comm"] == "mprotect_helper":
                mine += 1
            comms[raw["comm"]] += 1
            kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))
            d.submit("linux.mprotect", {"pid": raw["pid"], "anon": raw["anon"],
                                        "len": raw["len"], "comm": raw["comm"]})
            t0 = time.perf_counter()
            produced = d.tick()
            pipeline_lat.append((time.perf_counter() - t0) * 1000)
            verdicts += produced["verdicts"]

    for _ in range(10):
        subprocess.run(["/bin/true"], stdout=subprocess.DEVNULL)
    consume(time.time() + 0.8)
    control_events = len(events)

    helper_proc = subprocess.Popen([helper, str(MAPS)], cwd=workdir,
                                   stdout=subprocess.PIPE, text=True)
    consume(time.time() + 10.0)
    helper_out = helper_proc.communicate(timeout=20)[0].strip()
    consume(time.time() + 0.5)

    while d.pipeline.ingest.backlog_events() > 0:
        verdicts += d.tick()["verdicts"]
    health = d.health()
    rule_hits = d.engine.counts()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    d.stop()

    report = {
        "environment": {"python": sys.version.split()[0], "kernel": HOST.kernel},
        "helper_result": helper_out,
        "control_events": control_events,
        "events": len(events), "helper_events": mine,
        "top_comms": dict(comms.most_common(5)),
        "verdicts": verdicts, "rule_hits": rule_hits,
        "latency_kernel_to_user_ms": {
            "p50": round(statistics.median(kernel_lat), 3) if kernel_lat else None,
            "p95": p95(kernel_lat)},
        "latency_pipeline_ms": {
            "p50": round(statistics.median(pipeline_lat), 3) if pipeline_lat else None,
            "p95": p95(pipeline_lat)},
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "LSM file_mprotect; only newly added PROT_EXEC on anonymous memory alerts",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

