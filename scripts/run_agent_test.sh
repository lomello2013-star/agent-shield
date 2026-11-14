#!/bin/bash
set -u
killall fapolicyd 2>/dev/null
sleep 1
sudo python3 /home/aidf/aidf/linux_ebpf_agent.py --duration 12 \
  --out /tmp/agent_audit.jsonl &
AP=$!
sleep 3
/root/spike4/corr_helper 2
python3 /home/aidf/netprobe.py 4444
python3 /home/aidf/dnsprobe.py
wait $AP
systemctl start fapolicyd 2>/dev/null
echo LINES
wc -l /tmp/agent_audit.jsonl
echo RULES
python3 - <<'PY'
import json
from collections import Counter
c = Counter()
for line in open('/tmp/agent_audit.jsonl', encoding='utf-8'):
    c[json.loads(line)['verdict']['rule_id']] += 1
print(dict(c))
PY
