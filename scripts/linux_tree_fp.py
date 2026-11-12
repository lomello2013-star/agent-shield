"""False-positive measurement for tree correlation on a *legitimate* pattern.

Scenario L: a supervisor/debugger-like parent writes into a child (legitimate attach)
and the child JITs memory executable. The event pattern is identical to injection, so
the tree rule fires — this is a measured false positive, not a surprise.

Scenario B: the same child JITs, but nobody writes into it -> expected 0 alerts.

Writes artifacts/linux_tree_fp.json.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time

WORKSPACE = os.environ.get("AIDF_WORKSPACE", "/mnt/d/ИИ защитник Вектор-защитник")
sys.path.insert(0, WORKSPACE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

OUT = os.path.join(WORKSPACE, "artifacts", "linux_tree_fp.json")
HOST = HostContext(host_id="wsl-treefp", os="linux", version="26.04", arch="x64",
                   kernel=os.uname().release)


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
    for name in ("tree_helper", "mprotect_helper"):
        subprocess.run(["gcc", "-O2", "-o", name, os.path.join(src, f"{name}.c")],
                       cwd=workdir, check=True)
    return {name: os.path.join(workdir, name) for name in
            ("loader", "mem_write.bpf.o", "mprotect_exec.bpf.o",
             "tree_helper", "mprotect_helper")}


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_treefp_")
    bins = build(workdir)

    cfg = DaemonConfig(sources=["linux.memory", "linux.mprotect"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 200},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_tfpd_"), config=cfg, host=HOST,
               rules_path=os.path.join(WORKSPACE, "rules", "base.json"),
               log_fsync_every=64)
    d.start()

    def start(mode: str, obj: str) -> tuple[subprocess.Popen, "queue.Queue[str]"]:
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

    mem_proc, mem_q = start("stream_mem", "mem_write.bpf.o")
    mprot_proc, mprot_q = start("stream_mprotect", "mprotect_exec.bpf.o")

    submitted = {"linux.memory": 0, "linux.mprotect": 0}
    errors: list[str] = []

    def pump(q: "queue.Queue[str]", source: str, key: str, deadline: float) -> None:
        while time.time() < deadline:
            try:
                line = q.get(timeout=0.2).strip()
            except queue.Empty:
                return
            if not line.startswith("{"):
                continue
            raw = json.loads(line)
            if key not in raw:
                continue
            try:
                if source == "linux.memory":
                    d.submit(source, {"pid": raw["pid"], "target": raw["target"],
                                      "ppid": raw.get("ppid"), "comm": raw["comm"],
                                      "bytes": raw["bytes"]})
                else:
                    d.submit(source, {"pid": raw["pid"], "anon": raw["anon"],
                                      "ppid": raw.get("ppid"), "len": raw["len"],
                                      "comm": raw["comm"]})
                submitted[source] += 1
            except Exception as exc:  # noqa: BLE001 - diagnostics only
                errors.append(f"{source}: {type(exc).__name__}: {exc}")
            d.tick()

    def phase(helper: str, seconds: float) -> dict:
        before = dict(d.engine.counts())
        proc = subprocess.Popen([bins[helper], "5"], cwd=workdir, stdout=subprocess.PIPE,
                                text=True)
        end = time.time() + seconds
        while time.time() < end:
            pump(mem_q, "linux.memory", "target", time.time() + 0.05)
            pump(mprot_q, "linux.mprotect", "anon", time.time() + 0.05)
        out = proc.communicate(timeout=20)[0].strip()
        while d.pipeline.ingest.backlog_events() > 0:
            d.tick()
        after = d.engine.counts()
        return {"helper": out,
                "tree_alerts": after.get("LINUX-EXEC-CORR-109", 0) -
                               before.get("LINUX-EXEC-CORR-109", 0),
                "pid_alerts": after.get("LINUX-EXEC-CORR-108", 0) -
                              before.get("LINUX-EXEC-CORR-108", 0)}

    legit = phase("tree_helper", 8.0)        # supervisor writes + child JITs
    benign = phase("mprotect_helper", 6.0)   # JIT only, nobody writes into it

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
        "submitted": submitted, "adapter_errors": errors[:3],
        "legit_supervisor_plus_jit": legit,
        "benign_jit_only": benign,
        "known_fp": legit["tree_alerts"] > 0,
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "tree correlation cannot separate a legitimate attach+JIT from "
                "injection by event pattern alone; provenance is required",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
