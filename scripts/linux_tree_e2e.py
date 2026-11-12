"""Tree correlation: parent writes into the child, the child makes memory executable.

Compares two rules on the *same* stream:
  * LINUX-EXEC-CORR-108 groups by actor.pid  -> expected 0 (different pids)
  * LINUX-EXEC-CORR-109 groups by process tree -> expected >= 1

Writes artifacts/linux_tree.json.
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

WORKSPACE = os.environ.get("AIDF_WORKSPACE", "/mnt/d/Р В Р’В Р вЂ™Р’ВР В Р’В Р вЂ™Р’В Р В Р’В Р вЂ™Р’В·Р В Р’В Р вЂ™Р’В°Р В Р Р‹Р Р†Р вЂљР’В°Р В Р’В Р РЋРІР‚ВР В Р Р‹Р Р†Р вЂљРЎв„ўР В Р’В Р В РІР‚В¦Р В Р’В Р РЋРІР‚ВР В Р’В Р РЋРІР‚Сњ Р В Р’В Р Р†Р вЂљРІвЂћСћР В Р’В Р вЂ™Р’ВµР В Р’В Р РЋРІР‚СњР В Р Р‹Р Р†Р вЂљРЎв„ўР В Р’В Р РЋРІР‚СћР В Р Р‹Р В РІР‚С™-Р В Р’В Р вЂ™Р’В·Р В Р’В Р вЂ™Р’В°Р В Р Р‹Р Р†Р вЂљР’В°Р В Р’В Р РЋРІР‚ВР В Р Р‹Р Р†Р вЂљРЎв„ўР В Р’В Р В РІР‚В¦Р В Р’В Р РЋРІР‚ВР В Р’В Р РЋРІР‚Сњ")
sys.path.insert(0, WORKSPACE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

OUT = os.path.join(WORKSPACE, "artifacts", "linux_tree.json")
HOST = HostContext(host_id="wsl-tree", os="linux", version="26.04", arch="x64",
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
    subprocess.run(["gcc", "-O2", "-o", "tree_helper",
                    os.path.join(src, "tree_helper.c")], cwd=workdir, check=True)
    return {"loader": os.path.join(workdir, "loader"),
            "mem": os.path.join(workdir, "mem_write.bpf.o"),
            "mprot": os.path.join(workdir, "mprotect_exec.bpf.o"),
            "helper": os.path.join(workdir, "tree_helper")}


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_tree_")
    bins = build(workdir)

    cfg = DaemonConfig(sources=["linux.memory", "linux.mprotect"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 200},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_treed_"), config=cfg, host=HOST,
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

    mem_proc, mem_q = start("stream_mem", "mem")
    mprot_proc, mprot_q = start("stream_mprotect", "mprot")

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
                                      "ppid": raw.get("ppid"),
                                      "comm": raw["comm"], "bytes": raw["bytes"]})
                else:
                    d.submit(source, {"pid": raw["pid"], "anon": raw["anon"],
                                      "ppid": raw.get("ppid"),
                                      "len": raw["len"], "comm": raw["comm"]})
                submitted[source] += 1
            except Exception as exc:            # noqa: BLE001 - diagnostics only
                errors.append(f"{source}: {type(exc).__name__}: {exc}")
            d.tick()

    submitted = {"linux.memory": 0, "linux.mprotect": 0}
    errors = []
    before = dict(d.engine.counts())
    helper = subprocess.Popen([bins["helper"], "5", "5"], cwd=workdir,
                              stdout=subprocess.PIPE, text=True)
    end = time.time() + 8.0
    while time.time() < end:
        pump(mem_q, "linux.memory", "target", time.time() + 0.05)
        pump(mprot_q, "linux.mprotect", "anon", time.time() + 0.05)
    out = helper.communicate(timeout=20)[0]
    while d.pipeline.ingest.backlog_events() > 0:
        d.tick()
    after = d.engine.counts()
    pid_alerts = after.get("LINUX-EXEC-CORR-108", 0) - before.get("LINUX-EXEC-CORR-108", 0)
    tree_alerts = after.get("LINUX-EXEC-CORR-109", 0) - before.get("LINUX-EXEC-CORR-109", 0)
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
        "helper_output": out.strip().splitlines(),
        "submitted": submitted,
        "adapter_errors": errors[:3],
        "pid_group_alerts": pid_alerts,
        "tree_group_alerts": tree_alerts,
        "tree_beats_pid": tree_alerts > pid_alerts,
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "note": "parent writes, child executes: pid grouping cannot see it, tree grouping can",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()




