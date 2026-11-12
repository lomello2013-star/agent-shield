"""Provenance in correlation: does excluding trusted paths remove the supervisor+JIT FP?

Two scenarios with identical event patterns:
  L1 the supervisor binary lives in /usr/bin  -> CORR-110 must stay silent
  L2 the supervisor binary lives in /tmp      -> CORR-110 must fire

Process paths are resolved from /proc/<pid>/exe for every event (the kernel sources do
not carry argv[0]). Writes artifacts/linux_provenance.json.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time

WORKSPACE = os.environ.get("AIDF_WORKSPACE", "/mnt/d/Р В Р’ВР В Р’В Р В Р’В·Р В Р’В°Р РЋРІР‚В°Р В РЎвЂР РЋРІР‚С™Р В Р вЂ¦Р В РЎвЂР В РЎвЂќ Р В РІР‚в„ўР В Р’ВµР В РЎвЂќР РЋРІР‚С™Р В РЎвЂўР РЋР вЂљ-Р В Р’В·Р В Р’В°Р РЋРІР‚В°Р В РЎвЂР РЋРІР‚С™Р В Р вЂ¦Р В РЎвЂР В РЎвЂќ")
sys.path.insert(0, WORKSPACE)

from core.daemon import Daemon, DaemonConfig  # noqa: E402
from core.normalize import HostContext  # noqa: E402

OUT = os.path.join(WORKSPACE, "artifacts", "linux_provenance.json")
HOST = HostContext(host_id="wsl-prov", os="linux", version="26.04", arch="x64",
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


CURRENT_EXE = {"path": ""}
RESOLVED = {"kernel": 0, "proc": 0, "fallback": 0}


def exe_of(pid: int, comm: str = "", kernel_exe: str = "") -> str:
    """Kernel-provided path first (dentry walk), then /proc, then the lab fallback."""
    if kernel_exe:
        RESOLVED["kernel"] += 1
        return kernel_exe
    try:
        path = os.readlink(f"/proc/{pid}/exe")
        RESOLVED["proc"] += 1
        return path
    except OSError:
        pass
    if comm.startswith("aidf_tree"):
        RESOLVED["fallback"] += 1
        return CURRENT_EXE["path"]
    return ""


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="aidf_prov_")
    bins = build(workdir)
    trusted = "/usr/bin/aidf_tree_helper"
    untrusted = "/tmp/aidf_tree_helper"
    shutil.copyfile(bins["helper"], trusted)
    os.chmod(trusted, 0o755)
    shutil.copyfile(bins["helper"], untrusted)
    os.chmod(untrusted, 0o755)

    cfg = DaemonConfig(sources=["linux.memory", "linux.mprotect"],
                       thresholds={"heartbeat_timeout_s": 60, "alert_budget": 200},
                       queue={"capacity": 5000})
    d = Daemon(tempfile.mkdtemp(prefix="aidf_provd_"), config=cfg, host=HOST,
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
            raw["exe"] = exe_of(int(raw["pid"]), str(raw.get("comm") or ""),
                                str(raw.get("exe") or ""))
            if source == "linux.memory":
                d.submit(source, {"pid": raw["pid"], "target": raw["target"],
                                  "ppid": raw.get("ppid"), "exe": raw["exe"],
                                  "comm": raw["comm"], "bytes": raw["bytes"]})
            else:
                d.submit(source, {"pid": raw["pid"], "anon": raw["anon"],
                                  "ppid": raw.get("ppid"), "exe": raw["exe"],
                                  "len": raw["len"], "comm": raw["comm"]})
            d.tick()

    def scenario(binary: str, seconds: float = 8.0) -> dict:
        CURRENT_EXE["path"] = binary
        before = dict(d.engine.counts())
        proc = subprocess.Popen([binary, "5", "5"], cwd=workdir,
                                stdout=subprocess.PIPE, text=True)
        end = time.time() + seconds
        while time.time() < end:
            pump(mem_q, "linux.memory", "target", time.time() + 0.05)
            pump(mprot_q, "linux.mprotect", "anon", time.time() + 0.05)
        out = proc.communicate(timeout=20)[0].strip()
        while d.pipeline.ingest.backlog_events() > 0:
            d.tick()
        after = d.engine.counts()
        return {"helper": out,
                "corr_109_alerts": after.get("LINUX-EXEC-CORR-109", 0) -
                                   before.get("LINUX-EXEC-CORR-109", 0),
                "corr_110_alerts": after.get("LINUX-EXEC-CORR-110", 0) -
                                   before.get("LINUX-EXEC-CORR-110", 0)}

    trusted_run = scenario(trusted)
    untrusted_run = scenario(untrusted)

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
        "trusted_supervisor": {"path": trusted, **trusted_run},
        "untrusted_supervisor": {"path": untrusted, **untrusted_run},
        "fp_removed": trusted_run["corr_110_alerts"] == 0,
        "detection_kept": untrusted_run["corr_110_alerts"] > 0,
        "loss": health["ingest"]["lost"], "ledger_ok": health["ledger_ok"],
        "audit_chain_ok": health["audit_chain_ok"],
        "path_resolution": RESOLVED,
        "note": "same event pattern, only the binary path differs; CORR-110 adds "
                "provenance (untrusted path) to the correlation",
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()



