#!/bin/bash
mount -t securityfs none /sys/kernel/security 2>/dev/null
echo "=== IMA ==="
ls /sys/kernel/security/ima/ 2>&1
echo "policy_bytes=$(stat -c %s /sys/kernel/security/ima/policy 2>/dev/null || echo NA)"
echo "policy_rules=$(grep -c . /sys/kernel/security/ima/policy 2>/dev/null || echo 0)"
echo "violations=$(cat /sys/kernel/security/ima/violations 2>/dev/null || echo NA)"
echo "runtime_measurements=$(cat /sys/kernel/security/ima/runtime_measurements_count 2>/dev/null || echo NA)"
echo "=== fapolicyd / auditd present? ==="
for t in fapolicyd auditctl auditd; do printf "%s: " "$t"; command -v "$t" || echo MISSING; done
echo "=== kernel cmdline (ima/selinux/lsm) ==="
cat /proc/cmdline
echo "=== selinux ==="
cat /sys/fs/selinux/enforce 2>/dev/null || echo "selinuxfs not mounted"
echo "=== module signing ==="
zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(MODULE_SIG|MODULE_SIG_FORCE|MODULE_SIG_ALL|LOCK_DOWN_KERNEL)=' | sort
echo "=== kernel lockdown ==="
cat /sys/kernel/security/lockdown 2>/dev/null || echo "lockdown NA"
echo "=== fanotify ==="
grep -i fanotify /proc/config.gz 2>/dev/null | head -2 || true
