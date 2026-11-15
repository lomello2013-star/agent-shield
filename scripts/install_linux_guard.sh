#!/bin/bash
# Install the Linux kernel-level prevention daemon (fanotify). Run as root.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST=/opt/aidf
CONF=/etc/aidf

install -d "$DEST" "$CONF" /var/lib/aidf/guard
install -m 0755 "$ROOT/scripts/aidf_linux_guard.py" "$DEST/aidf_linux_guard.py"
install -m 0644 "$ROOT/packaging/linux/guard.toml" "$CONF/guard.toml"
install -m 0644 "$ROOT/packaging/linux/aidf-guard.service" /etc/systemd/system/aidf-guard.service
systemctl daemon-reload
systemctl enable aidf-guard
echo "installed guard; review $CONF/guard.toml (mode=audit) then: systemctl start aidf-guard"
