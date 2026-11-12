#!/bin/bash
echo "=== mount securityfs/bpffs ==="
mkdir -p /sys/kernel/security /sys/fs/bpf
mount -t securityfs none /sys/kernel/security 2>&1 || echo "securityfs mount failed rc=$?"
mount -t bpf bpf /sys/fs/bpf 2>&1 || echo "bpffs mount failed rc=$?"
echo "ACTIVE_LSM: $(cat /sys/kernel/security/lsm 2>&1)"
ls /sys/kernel/security/ 2>&1
echo "=== bpf syscall cap ==="
capsh --print 2>/dev/null | grep -i current || echo "no capsh"
echo "=== bpftool feature (program types) ==="
bpftool feature probe kernel 2>&1 | grep -E '^(eBPF|bpf|Program type|scalar|map type)' | head -5
bpftool feature probe kernel 2>&1 | grep -A40 'Supported program types' | head -45
echo "=== LSM support line ==="
bpftool feature probe kernel 2>&1 | grep -iE 'lsm|bpf_lsm' | head -10
echo "=== cgroup v2 ==="
mount | grep cgroup2
echo "=== modules present? ==="
ls /lib/modules/ 2>&1 | head -3
echo "=== fanotify/audit tools ==="
which auditctl fanotify 2>&1
