#!/bin/bash
echo "=== WSL secure boot / lockdown / efi ==="
ls /sys/firmware/efi 2>&1 | head -3
cat /sys/kernel/security/lockdown 2>/dev/null || echo "lockdown: NA"
echo "cmdline=$(cat /proc/cmdline)"
echo "=== ima/appraise ==="
mount -t securityfs none /sys/kernel/security 2>/dev/null
echo "ima_policy_bytes=$(stat -c %s /sys/kernel/security/ima/policy 2>/dev/null || echo NA)"
echo "=== kernel config: iommu/lockdown/lsm ==="
zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(SECURITY_LOCKDOWN|LSM=|IMA_APPRAISE|IMA_APPRAISE_BOOTPARAM|INTEGRITY|EFI)=' | sort | head -12
echo "=== mount options for / ==="
mount | grep ' / ' | head -2
