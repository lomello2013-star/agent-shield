#!/usr/bin/env python3
"""Linux eBPF agent prototype: run all loader streams, evaluate, audit JSONL.

Run as root with fapolicyd stopped for the BPF binaries:
  sudo python3 linux_ebpf_agent.py --duration 60 --out /tmp/aidf_audit.jsonl
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import linux_ebpf_live as mapper  # noqa: E402
from core.normalize import HostContext, Normalizer  # noqa: E402
from core.rules import RuleEngine, load_rules  # noqa: E402

STREAMS = [
    ("exec", "stream", "exec_path.bpf.o", []),
    ("open", "stream_open", "file_open_lsm.bpf.o", []),
    ("mprotect", "stream_mprotect", "mprotect_exec.bpf.o", []),
    ("procmem", "stream_procmem", "proc_mem.bpf.o", []),
    ("ptrace", "stream_ptrace", "ptrace_write.bpf.o", []),
    ("mem", "stream_mem", "mem_write.bpf.o", []),
    ("net", "stream_net", "net_connect_event.bpf.o", ["/sys/fs/cgroup"]),
    ("unlink", "stream_unlink", "unlink_lsm.bpf.o", []),
    ("sendto", "stream_sendto", "sendto_monitor.bpf.o", []),
    ("dns", "stream_dns", "dns_monitor.bpf.o", []),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--loader", default="/root/spike4/loader")
    ap.add_argument("--objects", default="/root/spike4")
    ap.add_argument("--duration", type=float, default=60.0,
                    help="seconds; 0 = until SIGINT")
    ap.add_argument("--out", default="/tmp/aidf_linux_audit.jsonl")
    args = ap.parse_args()

    normalizer = Normalizer(host=HostContext(
        host_id="aidf-linux-vm", os="linux", version="24.04", arch="x64"))
    engine = RuleEngine(load_rules([str(ROOT / "rules" / "base.json")]))
    lock = threading.Lock()
    out = open(args.out, "w", encoding="utf-8")
    procs: list[subprocess.Popen] = []

    def reader(name: str, proc: subprocess.Popen) -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or "pid" not in item:
                continue
            raw = mapper._raw(item)
            if raw is None:
                continue
            try:
                event = normalizer.normalize("linux.ebpf", raw)
                with lock:
                    verdicts = engine.evaluate(event)
                    for verdict in verdicts:
                        out.write(json.dumps({
                            "stream": name,
                            "verdict": verdict.model_dump(mode="json"),
                            "event": event.model_dump(mode="json"),
                        }, ensure_ascii=False) + "\n")
                        out.flush()
            except Exception as exc:  # noqa: BLE001 - keep the agent alive
                print(f"agent[{name}]: {type(exc).__name__}: {exc}",
                      file=sys.stderr, flush=True)

    for name, mode, obj, extra in STREAMS:
        path = str(pathlib.Path(args.objects) / obj)
        if not pathlib.Path(path).exists():
            print(f"agent: missing {path}", file=sys.stderr, flush=True)
            continue
        cmd = [args.loader, mode, path, *extra, "0"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
        procs.append(proc)
        threading.Thread(target=reader, args=(name, proc), daemon=True).start()
        print(f"agent: {name} -> {mode} {obj}", file=sys.stderr, flush=True)

    print(f"agent: {len(procs)} streams, audit={args.out}", file=sys.stderr, flush=True)
    try:
        if args.duration <= 0:
            while True:
                time.sleep(1)
        else:
            time.sleep(args.duration)
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        out.close()
    print("agent: stopped", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
