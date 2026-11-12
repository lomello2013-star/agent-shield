#!/bin/bash
echo "=== kernel ==="
uname -a
echo "=== sudo ==="
sudo -n true 2>&1 && echo "SUDO_NOPASS_OK" || echo "SUDO_NEEDS_PASS"
echo "=== config bpf/net ==="
zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(BPF_LSM|DEBUG_INFO_BTF|BPF_SYSCALL|BPF_JIT|CGROUP_BPF|NET_CLS_BPF|NET_ACT_BPF|NET_SCH_INGRESS|XDP_SOCKETS|FANOTIFY|MODULE_SIG|AUDIT|SECURITY_LSM|LSM=|IMA|SECURITYFS|CGROUP_BPF)=' | sort
echo "=== lsm list ==="
cat /sys/kernel/security/lsm 2>&1
echo "=== cgroup ==="
stat -fc %T /sys/fs/cgroup 2>&1; cat /proc/self/cgroup
echo "=== tools ==="
for t in bpftool clang llvm-strip gcc make python3 bpftrace nft auditctl; do printf '%s: ' "$t"; command -v "$t" || echo MISSING; done
echo "=== btf size ==="
stat -c %s /sys/kernel/btf/vmlinux
echo "=== os-release ==="
. /etc/os-release; echo "$PRETTY_NAME"
echo "=== caps ==="
grep CapEff /proc/self/status
