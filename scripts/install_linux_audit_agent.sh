#!/bin/bash
# Install the Linux auditd agent (no eBPF required). Run from repo root as root:
#   sudo bash scripts/install_linux_audit_agent.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST=/opt/aidf
CONF=/etc/aidf

install -d "$DEST" "$CONF" /var/lib/aidf /var/log/aidf
cp -r "$ROOT/core" "$ROOT/schemas" "$ROOT/rules" "$DEST/"
install -m 0644 "$ROOT/scripts/aidf_agent.py" "$DEST/aidf_agent.py"
install -d "$DEST/docs"
install -m 0644 "$ROOT/docs/linux-auditd.md" "$DEST/docs/linux-auditd.md" 2>/dev/null || true
install -d "$DEST/agent/gui"
install -m 0644 "$ROOT/agent/gui/index.html" "$DEST/agent/gui/index.html"
if [ ! -f "$CONF/agent.toml" ]; then
    install -m 0644 "$ROOT/packaging/linux/agent.toml" "$CONF/agent.toml"
fi
install -m 0644 "$ROOT/packaging/linux/aidf-auditd.service" \
    /etc/systemd/system/aidf-auditd.service
systemctl daemon-reload
systemctl enable aidf-auditd
echo "installed: $DEST; edit $CONF/agent.toml, then: systemctl start aidf-auditd"
