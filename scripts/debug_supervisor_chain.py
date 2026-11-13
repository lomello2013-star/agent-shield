"""Debug: why the supervisor measurement could not verify the audit chain."""

import glob
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from core.selfprotect import HashChainLog

root = tempfile.mkdtemp(prefix="aidf_dbg_")
ready = os.path.join(root, "ready.txt")
proc = subprocess.Popen([sys.executable, os.path.join(HERE, "scripts", "daemon_child.py")],
                        env=dict(os.environ, AIDF_CHILD_ROOT=root,
                                 AIDF_CHILD_READY_FILE=ready,
                                 PYTHONIOENCODING="utf-8"),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.time() + 30
while time.time() < deadline and not os.path.exists(ready):
    time.sleep(0.02)
print("ready:", os.path.exists(ready))
time.sleep(2.0)
found = glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True)
print("jsonl files:", found)
proc.kill()
proc.wait(timeout=10)
time.sleep(0.5)
print("after kill:", glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True))
for path in glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True):
    log = HashChainLog(path, anchor_path=os.path.join(os.path.dirname(path), "anchor.json"))
    state = log.verify()
    print("verify", os.path.basename(path), "ok=", state.ok, "records=", state.records)
print("root:", root)
