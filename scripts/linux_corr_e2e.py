"""Correlation measurement: does mprotect+injection produce an alert, and does the
correlation suppress the JIT-only noise?

Three phases, same daemon and rules:
  A correlated  — one process writes into a child and mprotects its own pages
  B mprotect-only — JIT-like: many mprotect(PROT_EXEC), no cross-process writes
  C inject-only  — cross-process writes, no exec transition

Writes artifacts/linux_corr.json.
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

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

OUT = os.path.join(WORKSPACE, "artifacts", "linux_corr.json")
HOST = HostContext(host_id="wsl-corr", os="linux", version="26.04", arch="x64",
                   kernel=os.uname().release)
N = 5


def p95(values):
    s = sorted(values)
    return round(s[min(len(s) - 1, int(len(s) * 0.95))], 3)


def build(workdir: str) -> dict[str, str]:
    src = os.path.join(WORKSPACE, "spikes", "04-ebpf")
    for name in ("mem_write.bpf.c", "mprotect_exec.bpf.c", "loader.c"):
        subprocess.run(["cp", os.path.join(src, name), workdir], check=True)
    with open(os.path.join(workdir, "vmlinux.h"), "w") as fh:
        subprocess.run(["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux",
                        "format", "c"], stdout=fh, check=True)
    for name in ("mem_write", "mprotect_exec"):
        subprocess.run(["clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86",
                        "-I.", "-c", f"{name}.bpf.c", "-o", f"{name}.bpf.o"],
                       cwd=workdir, check=True)
    subprocess.run(["gcc", "-O2", "-o", "loader", "loader.c", "-lbpf", "-lz", "-lelf"],
                   cwd=workdir, check=True)
    for name in ("corr_helper", "mprotect_helper", "memwrite_helper"):
        subprocess.run(["gcc", "-O2", "-o", name, os.path.join(src, f"{name}.c")],
                       cwd=workdir, check=True)
    return {name: os.path.join(workdir, name) for name in
            ("loader", "mem_write.bpf.o", "mprotect_exec.bpf.o",
             "corr_helper", "mprotect_helper", "memwrite_helper")}


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_corr_")
    bins = build(workdir)

    cfg = DaemonConfig(sources=["linux.memory", "linux.mprotect"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 200},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_corrd_"), config=cfg, host=HOST,
               rules_path=os.path.join(WORKSPACE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()

    def start_loader(mode: str, obj: str) -> tuple[subprocess.Popen, "queue.Queue[str]"]:
        proc = subprocess.Popen([bins["loader"], mode, bins[obj], "0"],
                                stdout=subprocess.PIPE, text=True, bufsize=1,
                                cwd=workdir, stderr=subprocess.PIPE)
        q: "queue.Queue[str]" = queue.Queue()
        threading.Thread(target=lambda: [q.put(l) for l in proc.stdout], daemon=True).start()
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                if '"ready":true' in q.get(timeout=0.5):
                    break
            except queue.Empty:
                continue
        return proc, q

    mem_proc, mem_q = start_loader("stream_mem", "mem_write.bpf.o")
    mprot_proc, mprot_q = start_loader("stream_mprotect", "mprotect_exec.bpf.o")

    stats = {"mem_events": 0, "mprot_events": 0, "verdicts": 0,
             "corr_alerts": 0, "signal_alerts": 0}
    lat: list[float] = []

    def lane(q: "queue.Queue[str]", source: str, counter: str, action_key: str) -> None:
        try:
            line = q.get(timeout=0.2).strip()
        except queue.Empty:
            return
        if not line.startswith("{"):
            return
        raw = json.loads(line)
        if action_key not in raw:
            return
        stats[counter] += 1
        lat.append(0.0)
        if source == "linux.memory":
            d.submit(source, {"pid": raw["pid"], "target": raw["target"],
                              "comm": raw["comm"], "bytes": raw["bytes"]})
        else:
            d.submit(source, {"pid": raw["pid"], "anon": raw["anon"],
                              "len": raw["len"], "comm": raw["comm"]})
        produced = d.tick()
        stats["verdicts"] += produced["verdicts"]

    def drain(deadline_ts: float) -> None:
        while time.time() < deadline_ts:
            lane(mem_q, "linux.memory", "mem_events", "target")
            lane(mprot_q, "linux.mprotect", "mprot_events", "anon")

    def run(kind: str, seconds: float = 6.0) -> dict:
        stats["corr_alerts"] = 0
        stats["signal_alerts"] = 0
        before = dict(d.engine.counts())
        helper = {"corr": "corr_helper", "mprot": "mprotect_helper",
                  "inject": "memwrite_helper"}[kind]
        arg = str(N if kind == "corr" else 20)
        proc = subprocess.Popen([bins[helper], arg], cwd=workdir,
                                stdout=subprocess.PIPE, text=True)
        drain(time.time() + seconds)
        out = proc.communicate(timeout=20)[0].strip()
        drain(time.time() + 0.5)
        while d.pipeline.ingest.backlog_events() > 0:
            stats["verdicts"] += d.tick()["verdicts"]
        after = d.engine.counts()
        corr = after.get("LINUX-EXEC-CORR-108", 0) - before.get("LINUX-EXEC-CORR-108", 0)
        signal = after.get("LINUX-EXEC-MEM-107", 0) - before.get("LINUX-EXEC-MEM-107", 0)
        return {"helper": out, "corr_alerts": corr, "signal_alerts": signal,
                "events": stats["mem_events"] + stats["mprot_events"]}

    phases = {"correlated": run("corr"), "mprotect_only": run("mprot"),
              "inject_only": run("inject")}
    health = d.health()
    for proc in (mem_proc, mprot_proc):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    d.stop()

    report = {
        "environment": {"python": sys.version.split()[0], "kernel": HOST.kernel},
        "phases": phases,
        "corr_alerts_correlated": phases["correlated"]["corr_alerts"],
        "corr_alerts_mprotect_only": phases["mprotect_only"]["corr_alerts"],
        "corr_alerts_inject_only": phases["inject_only"]["corr_alerts"],
        "jit_noise_suppressed": (phases["mprotect_only"]["corr_alerts"] == 0 and
                                 phases["mprotect_only"]["signal_alerts"] > 0),
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "correlation fires only when mprotect(EXEC,anon) and a cross-process "
                "write happen in the same process inside 5 s",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
