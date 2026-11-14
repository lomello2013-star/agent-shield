#!/bin/bash
set -u
killall fapolicyd 2>/dev/null
sleep 1
timeout 12 /root/spike4/loader stream_open /root/spike4/file_open_lsm.bpf.o 50 \
  > /tmp/filewrite50.jsonl 2>/tmp/filewrite50.err &
LP=$!
sleep 1
for i in $(seq 1 50); do
  touch "/tmp/aidf_write_$i"
done
wait $LP
systemctl start fapolicyd 2>/dev/null
wc -l /tmp/filewrite50.jsonl
