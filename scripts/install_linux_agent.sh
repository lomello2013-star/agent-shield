#!/bin/bash
# Install the Linux eBPF agent. Run from the repo root as root.
#   sudo bash scripts/install_linux_agent.sh /root/spike4
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=${1:-/root/spike4}
DEST=/opt/aidf

install -d "$DEST" /var/log/aidf
cp -r "$ROOT/core" "$ROOT/schemas" "$ROOT/rules" "$DEST/"
install -m 0644 "$ROOT/scripts/linux_ebpf_agent.py" "$DEST/linux_ebpf_agent.py"
install -m 0644 "$ROOT/scripts/linux_ebpf_live.py" "$DEST/linux_ebpf_live.py"
install -d "$DEST/docs"
install -m 0644 "$ROOT/docs/linux-agent.md" "$DEST/docs/linux-agent.md"

install -m 0755 "$SRC/loader" "$DEST/loader"
for obj in "$SRC"/*.bpf.o; do
    install -m 0644 "$obj" "$DEST/"
done

install -m 0644 "$ROOT/packaging/linux/aidf-agent.service" \
    /etc/systemd/system/aidf-agent.service
install -m 0644 "$ROOT/packaging/linux/aidf-agent.logrotate" \
    /etc/logrotate.d/aidf-agent
systemctl daemon-reload
systemctl enable aidf-agent
echo "installed: $DEST; start with: systemctl start aidf-agent"
