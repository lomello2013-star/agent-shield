"""Collect facts for the readiness assessment (agent + server)."""

from __future__ import annotations

import glob
import io
import json
import os
import re

print("schemas:", len(glob.glob("schemas/**/*.json", recursive=True)) + len(glob.glob("schemas/*.json")))
print("rules:", len(json.load(open("rules/base.json", encoding="utf-8"))["rules"]))

app = io.open("stml/server/app.py", encoding="utf-8").read()
routes = sorted(set(re.findall(r'"(/v0/[a-z_/]+)"', app)))
print("stml routes:", routes)

for folder in ("deploy/windows", "deploy/linux", "deploy/policy", "packaging/windows",
               "packaging/linux", "packaging/policy", "driver/minifilter"):
    if os.path.isdir(folder):
        names = sorted(os.listdir(folder))
        print(f"{folder}: {names[:8]}")

# where is the linux agent?
hits = []
for pattern in ("**/*agent*.rs", "**/*agent*.py", "**/*.service", "**/*.bpf.c"):
    for path in glob.glob(pattern, recursive=True):
        if "node_modules" in path or ".venv" in path:
            continue
        hits.append(path)
print("agent-ish files:", len(hits))
for path in sorted(hits)[:25]:
    print("  ", path)
