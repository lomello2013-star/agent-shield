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
        if "pid" not in item or "filename" not in item:
            continue
        raw = {
            "category": "process.start",
            "action": "execve",
            "pid": item["pid"],
            "ppid": item.get("ppid"),
            "comm": item.get("comm", ""),
            "exe": item["filename"],
            "cmdline": item["filename"],
        }
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
