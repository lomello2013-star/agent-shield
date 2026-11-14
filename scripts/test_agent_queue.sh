#!/bin/bash
set -u
killall fapolicyd 2>/dev/null
sleep 1
sudo python3 /home/aidf/aidf/linux_ebpf_agent.py --objects /root/spike4 \
  --manifest /home/aidf/objects.sha256 --duration 10 \
  --out /tmp/agent_queue_audit.jsonl &
AP=$!
sleep 4
/root/spike4/corr_helper 1
python3 /home/aidf/netprobe.py 4444
python3 /home/aidf/dnsprobe.py
wait $AP
systemctl start fapolicyd 2>/dev/null
echo LINES
wc -l /tmp/agent_queue_audit.jsonl
