#!/bin/bash
# Run the Linux end-to-end bridge inside WSL as root:
#   eBPF exec tracepoint -> aidfd -> verdicts, with measurements.
set -u
VENV=/root/aidf-venv
WORKSPACE="/mnt/d/ИИ защитник Вектор-защитник"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV" >/dev/null 2>&1 || { echo "venv failed"; exit 1; }
fi
"$VENV/bin/pip" install -q --disable-pip-version-check pydantic cryptography 2>&1 | tail -2
export AIDF_WORKSPACE="$WORKSPACE"
cd /root || exit 1
"$VENV/bin/python" "$WORKSPACE/scripts/linux_e2e.py"
