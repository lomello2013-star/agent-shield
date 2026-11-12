#!/bin/bash
# LSM file_open bridge inside WSL as root (credential-file access detection).
set -u
VENV=/root/aidf-venv
WORKSPACE="/mnt/d/ИИ защитник Вектор-защитник"
export AIDF_WORKSPACE="$WORKSPACE"
cd /root || exit 1
"$VENV/bin/python" "$WORKSPACE/scripts/linux_lsm_e2e.py"
