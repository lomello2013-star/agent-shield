#!/bin/bash
# Cross-process memory-write detection inside WSL as root.
set -u
VENV=/root/aidf-venv
WORKSPACE="/mnt/d/ИИ защитник Вектор-защитник"
export AIDF_WORKSPACE="$WORKSPACE"
cd /root || exit 1
"$VENV/bin/python" "$WORKSPACE/scripts/linux_mem_e2e.py"
