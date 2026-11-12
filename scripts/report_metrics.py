"""One-off metrics collection for the development report (read-only)."""

import glob
import io
import json
import os
import re

ROOT = "."
out = {}

run_all = json.load(open("artifacts/run_all.json", encoding="utf-8"))
out["run_all"] = {
    "steps": [(s["name"], s["ok"], s["duration_s"]) for s in run_all["steps"]],
    "passed": run_all["passed"],
    "total": len(run_all["steps"]),
    "failed_required": run_all["failed_required"],
    "total_s": run_all["total_s"],
    "generated_at": run_all["generated_at"],
}

rules = json.load(open("rules/base.json", encoding="utf-8-sig"))["rules"]
out["rules"] = {
    "count": len(rules),
    "prevention": sum(1 for r in rules if r.get("prevention")),
    "correlated": sum(1 for r in rules if r.get("correlate")),
    "windowed": sum(1 for r in rules if r.get("window_sec")),
    "by_platform": {
        "windows": sum(1 for r in rules if r["match"].get("platform") == "windows"),
        "linux": sum(1 for r in rules if r["match"].get("platform") == "linux"),
        "any": sum(1 for r in rules if "platform" not in r["match"]),
    },
}
techniques = json.load(open("rules/techniques.json", encoding="utf-8-sig"))
out["techniques"] = len(techniques.get("techniques", techniques))

out["schemas"] = {
    "json_files": len(glob.glob("schemas/v3/json_schema/*.json")),
}

core = sorted(glob.glob("core/*.py"))
tests = sorted(glob.glob("tests/*.py"))
scripts = sorted(glob.glob("scripts/*.py"))


def loc(files):
    total = 0
    for path in files:
        with io.open(path, encoding="utf-8") as fh:
            total += sum(1 for _ in fh)
    return total


out["size"] = {
    "core_files": len(core), "core_loc": loc(core),
    "test_files": len(tests), "test_loc": loc(tests),
    "script_files": len(scripts), "script_loc": loc(scripts),
    "bpf_files": len(glob.glob("spikes/04-ebpf/*.bpf.c")),
}

devlog = io.open("DEVLOG.md", encoding="utf-8").read()
entries = re.findall(r"^## \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\] (.+?) \[(\w+)\]$",
                     devlog, re.M)
out["devlog"] = {
    "entries": len(entries),
    "first": entries[0][0] if entries else None,
    "last": entries[-1][0] if entries else None,
    "types": {t: sum(1 for e in entries if e[2] == t) for t in
              sorted({e[2] for e in entries})},
}

artifacts = sorted(os.path.basename(p) for p in glob.glob("artifacts/*.json"))
out["artifacts"] = {"count": len(artifacts), "names": artifacts}
out["docs"] = sorted(os.path.basename(p) for p in glob.glob("docs/*.md"))

with open("artifacts/report_metrics.json", "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=2, ensure_ascii=False)
print("metrics written:", len(out["artifacts"]["names"]), "artifacts,", out["devlog"]["entries"], "devlog entries")

