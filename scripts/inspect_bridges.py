import io
import re

FILES = {
    "scripts/linux_e2e.py": "linux.ebpf",
    "scripts/linux_lsm_e2e.py": "linux.lsm",
    "scripts/linux_net_e2e.py": "linux.net",
}

for path in FILES:
    text = io.open(path, encoding="utf-8").read()
    print("===", path, "has report:", "report = {" in text)
    for i, line in enumerate(text.splitlines(), 1):
        if "report = {" in line or "events" in line and ":" in line and "def " not in line:
            print("  ", i, line.strip()[:110])
