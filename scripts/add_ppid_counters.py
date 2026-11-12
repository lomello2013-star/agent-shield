"""F05: count how many exec/LSM/net events carry a parent pid (ppid).

Adds a `ppid_events` counter to each bridge so the propagation of ppid is measured as
part of the normal regression run instead of being asserted.
"""

import io

PATCHES = {
    "scripts/linux_e2e.py": [
        ("verdicts = 0", "verdicts = 0\n    ppid_ok = 0"),
        ('kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))     # ms',
         'kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))     # ms\n'
         '        if int(raw.get("ppid") or 0) > 0:\n            ppid_ok += 1'),
        ('"events": len(kernel_lat), "elapsed_s": round(elapsed, 2),',
         '"events": len(kernel_lat), "ppid_events": ppid_ok,\n        "elapsed_s": round(elapsed, 2),'),
    ],
    "scripts/linux_lsm_e2e.py": [
        ("verdicts = 0", "verdicts = 0\n    ppid_ok = 0"),
        ('kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))',
         'kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))\n'
         '        if int(raw.get("ppid") or 0) > 0:\n            ppid_ok += 1'),
        ('"events": len(kernel_lat), "sensitive_reads": SENSITIVE,',
         '"events": len(kernel_lat), "ppid_events": ppid_ok,\n        "sensitive_reads": SENSITIVE,'),
    ],
    "scripts/linux_net_e2e.py": [
        ("verdicts = 0", "verdicts = 0\n    ppid_ok = 0"),
        ('kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))',
         'kernel_lat.append(max(0, (t_recv - int(raw["ts_ns"])) / 1e6))\n'
         '        if int(raw.get("ppid") or 0) > 0:\n            ppid_ok += 1'),
        ('"events": len(kernel_lat), "ports_seen": ports_seen,',
         '"events": len(kernel_lat), "ppid_events": ppid_ok,\n        "ports_seen": ports_seen,'),
    ],
}

for path, replacements in PATCHES.items():
    text = io.open(path, encoding="utf-8").read()
    for old, new in replacements:
        if old not in text:
            print(f"{path}: MISSING anchor -> {old[:50]!r}")
            continue
        text = text.replace(old, new, 1)
    io.open(path, "w", encoding="utf-8", newline="\n").write(text)
    print(path, "ppid_ok:", text.count("ppid_ok"), "reported:",
          '"ppid_events": ppid_ok' in text)
