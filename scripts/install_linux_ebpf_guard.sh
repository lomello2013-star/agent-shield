#!/bin/bash
# Install the eBPF LSM prevention path. Requires a kernel with CONFIG_BPF_LSM
# and `lsm=...,bpf` on the kernel command line. Run as root.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST=/opt/aidf
CONF=/etc/aidf

install -d "$DEST" "$CONF"
if [ ! -f "$DEST/aidf_enforce.bpf.o" ] || [ ! -x "$DEST/aidf-enforce" ]; then
    echo "missing $DEST/aidf_enforce.bpf.o or aidf-enforce; build with scripts/build_linux_ebpf.sh" >&2
    exit 2
fi
install -m 0644 "$ROOT/packaging/linux/enforce.policy" "$CONF/enforce.policy"
install -m 0644 "$ROOT/packaging/linux/aidf-ebpf-guard.service" /etc/systemd/system/aidf-ebpf-guard.service
systemctl daemon-reload
systemctl enable aidf-ebpf-guard
echo "installed; review $CONF/enforce.policy; start with: systemctl start aidf-ebpf-guard"
