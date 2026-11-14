#!/usr/bin/env python3
"""Map live eBPF exec JSONL (spike loader) through the product normalizer/rules."""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path("/home/aidf/aidf")
sys.path.insert(0, str(ROOT))

from core.normalize import HostContext, Normalizer  # noqa: E402
from core.rules import RuleEngine, load_rules  # noqa: E402


def main(path: str) -> int:
    normalizer = Normalizer(host=HostContext(
        host_id="aidf-linux-vm", os="linux", version="24.04", arch="x64"))
    engine = RuleEngine(load_rules([str(ROOT / "rules" / "base.json")]))
    events = 0
    verdicts: list[str] = []
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "pid" not in item:
            continue
        raw = {
            "pid": item["pid"],
            "ppid": item.get("ppid"),
            "comm": item.get("comm", ""),
        }
        if "filename" in item:
            raw.update(category="process.start", action="execve",
                       exe=item["filename"], cmdline=item["filename"])
        elif "anon" in item:
            raw.update(category="memory.access", action="mprotect_exec",
                       exe=item.get("exe", ""), cmdline=item.get("exe", ""),
                       anon=item["anon"], len=item.get("len"))
        elif "writable" in item:
            raw.update(category="memory.access", action="proc_mem",
                       exe=item.get("comm", ""), cmdline=item.get("comm", ""),
                       writable=item["writable"])
        elif "request" in item:
            raw.update(category="memory.access", action="ptrace",
                       exe=item.get("comm", ""), cmdline=item.get("comm", ""),
                       request=item["request"], target=item.get("target"))
        elif "bytes" in item:
            raw.update(category="memory.access", action="vm_write",
                       exe=item.get("exe", ""), cmdline=item.get("exe", ""),
                       bytes=item["bytes"], target=item.get("target"))
        elif "dport" in item:
            raw.update(category="net.connect", action="connect",
                       exe=item.get("comm", ""), cmdline=item.get("comm", ""),
                       daddr=item.get("daddr", ""), dport=item["dport"],
                       proto="tcp")
        elif "path" in item:
            path = item["path"]
            if path.startswith(("/etc/cron", "/var/spool/cron", "/etc/crontab")):
                category, action = "persistence.change", "cron_write"
            elif path.startswith(("/etc/audit", "/var/log/audit")):
                category, action = "log.tamper", "audit_tamper"
            else:
                category, action = "file.read", "open"
            raw.update(category=category, action=action,
                       exe=item.get("comm", ""), cmdline=item.get("comm", ""),
                       filename=path)
        else:
            continue
        try:
            event = normalizer.normalize("linux.ebpf", raw)
        except Exception as exc:  # noqa: BLE001 - diagnostic path
            print("NORM_ERR", type(exc).__name__, exc)
            continue
        events += 1
        for verdict in engine.evaluate(event):
            verdicts.append(verdict.rule_id)
            print("VERDICT", verdict.rule_id, event.actor.path if event.actor else "")
    print("SUMMARY", json.dumps({"events": events, "verdicts": verdicts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/exec.jsonl"))
