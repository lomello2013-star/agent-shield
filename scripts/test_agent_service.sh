#!/bin/bash
set -u
killall fapolicyd 2>/dev/null
sleep 1
cd /home/aidf/aidf
bash scripts/install_linux_agent.sh /root/spike4
systemctl start aidf-agent
sleep 10
/root/spike4/corr_helper 2
python3 /home/aidf/netprobe.py 4444
python3 /home/aidf/dnsprobe.py
sleep 2
systemctl stop aidf-agent
systemctl start fapolicyd 2>/dev/null
echo LINES
wc -l /var/log/aidf/linux_audit.jsonl
echo STATUS
systemctl status aidf-agent --no-pager | head -6
