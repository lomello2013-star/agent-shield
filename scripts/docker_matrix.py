"""Container matrix probe: what a Linux container target actually exposes.

Containers share the host kernel, so BTF/LSM/eBPF availability depends on mounts and
capabilities, not on the image. This script measures that instead of assuming it.

Writes artifacts/docker_matrix.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(HERE, "artifacts", "docker_matrix.json")
IMAGE = os.environ.get("AIDF_DOCKER_IMAGE", "redis:7-alpine")

PROBE = (
    "echo kernel=$(uname -r); "
    "echo btf=$(stat -c %s /sys/kernel/btf/vmlinux 2>/dev/null || echo MISSING); "
    "echo lsm=$(cat /sys/kernel/security/lsm 2>/dev/null || echo NO_SECURITYFS); "
    "echo securefs=$(mount | grep -c securityfs); "
    "echo capeff=$(grep CapEff /proc/self/status | awk '{print $2}'); "
    "echo unpriv_bpf=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo NA); "
    "echo cgroup=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo NA); "
    "echo bpf_fs=$(mount | grep -c ' type bpf'); "
    "echo modules=$(ls /lib/modules 2>/dev/null | wc -l)"
)


def run(name: str, extra: list[str], command: str = PROBE) -> dict:
    argv = ["docker", "run", "--rm", *extra, IMAGE, "sh", "-c", command]
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"case": name, "error": "timeout"}
    parsed = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            parsed[key.strip()] = value.strip()
    return {"case": name, "image": IMAGE, "exit_code": completed.returncode,
            "values": parsed, "stderr": completed.stderr.strip()[:400]}


def main() -> None:
    report = {
        "cases": [
            run("default", []),
            run("privileged", ["--privileged"]),
            run("caps_bpf_sysadmin_btf_mount",
                ["--cap-add", "SYS_ADMIN", "--cap-add", "BPF",
                 "-v", "/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro"]),
        ],
        "note": "containers inherit the host kernel; BTF/LSM visibility depends on mounts "
                "and capabilities, not on the image",
    }
    # decode capabilities into names for readability
    names = {0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER", 4: "FSETID",
             5: "KILL", 6: "SETGID", 7: "SETUID", 8: "SETPCAP", 9: "LINUX_IMMUTABLE",
             10: "NET_BIND_SERVICE", 11: "NET_BROADCAST", 12: "NET_ADMIN", 13: "NET_RAW",
             14: "IPC_LOCK", 15: "IPC_OWNER", 16: "SYS_MODULE", 17: "SYS_RAWIO",
             18: "SYS_CHROOT", 19: "SYS_PTRACE", 20: "SYS_PACCT", 21: "SYS_ADMIN",
             22: "SYS_BOOT", 23: "SYS_NICE", 24: "SYS_RESOURCE", 25: "SYS_TIME",
             26: "SYS_TTY_CONFIG", 27: "MKNOD", 28: "LEASE", 29: "AUDIT_WRITE",
             30: "AUDIT_CONTROL", 31: "SETFCAP", 32: "MAC_OVERRIDE", 33: "MAC_ADMIN",
             34: "SYSLOG", 35: "WAKE_ALARM", 36: "BLOCK_SUSPEND", 37: "AUDIT_READ",
             38: "PERFMON", 39: "BPF", 40: "CHECKPOINT_RESTORE"}
    for case in report["cases"]:
        cap_hex = case.get("values", {}).get("capeff")
        if cap_hex:
            mask = int(cap_hex, 16)
            case["capabilities"] = [names[i] for i in range(41) if mask & (1 << i)]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
