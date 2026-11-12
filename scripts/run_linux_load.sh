#!/bin/bash
# Linux load run inside WSL as root (10k real exec events).
set -u
VENV=/root/aidf-venv
WORKSPACE="/mnt/d/ИИ защитник Вектор-защитник"
export AIDF_WORKSPACE="$WORKSPACE"
export AIDF_LOAD_EVENTS="${AIDF_LOAD_EVENTS:-10000}"
cd /root || exit 1
"$VENV/bin/python" "$WORKSPACE/scripts/linux_load.py"
