#!/bin/bash
# Linux VM acceptance test for the kernel guard. Run inside a disposable VM.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CONF=/tmp/aidf-guard-test.toml
cat > "$CONF" <<'EOF'
[guard]
mode = "audit"
mark_path = "/"
deny_exec = ["/tmp/"]
protect_write = []
allow_write_processes = []
EOF

echo "== fanotify audit =="
sudo python3 "$ROOT/scripts/aidf_linux_guard.py" --config "$CONF" --out /tmp/aidf-guard-events.jsonl &
GPID=$!
sleep 1
cp /bin/true /tmp/aidf-guard-test
chmod +x /tmp/aidf-guard-test
/tmp/aidf-guard-test
sleep 1
kill "$GPID" 2>/dev/null || true
test -s /tmp/aidf-guard-events.jsonl && echo "audit_event=ok" || { echo "audit_event=missing"; exit 1; }

echo "== fanotify enforce =="
sed -i 's/mode = "audit"/mode = "enforce"/' "$CONF"
sudo python3 "$ROOT/scripts/aidf_linux_guard.py" --config "$CONF" --out /tmp/aidf-guard-events.jsonl &
GPID=$!
sleep 1
if /tmp/aidf-guard-test; then echo "enforce=FAILED (exec allowed)"; kill "$GPID"; exit 1; else echo "enforce=denied"; fi
kill "$GPID" 2>/dev/null || true

echo "== eBPF LSM (if available) =="
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    python3 "$ROOT/scripts/build_linux_ebpf.sh" /tmp/aidf-ebpf >/dev/null
    sudo /tmp/aidf-ebpf/aidf-enforce audit /tmp/aidf-ebpf/aidf_enforce.bpf.o /etc/aidf/enforce.policy &
    GPID=$!
    sleep 1
    /tmp/aidf-guard-test || true
    kill "$GPID" 2>/dev/null || true
    echo "ebpf=checked"
else
    echo "ebpf=unavailable (no bpf in /sys/kernel/security/lsm)"
fi
