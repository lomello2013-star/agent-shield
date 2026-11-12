#!/bin/bash
# Spike 4 (net part) / Spike 7 (Linux): per-cgroup egress drop via cgroup_skb/egress.
set -u
SRC="$1"
WORK=/root/spike4
mkdir -p "$WORK"
cp "$SRC"/*.c "$WORK"/ 2>/dev/null
cd "$WORK" || exit 1
mount -t securityfs none /sys/kernel/security 2>/dev/null
echo "active_lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)"

echo "=== recompile net prog ==="
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c net_cgroup.bpf.c -o net_cgroup.bpf.o && echo "compile_ok bytes=$(stat -c %s net_cgroup.bpf.o)"

CG=/sys/fs/cgroup/spike
mkdir -p "$CG"
echo "cgroup=$CG controllers=$(cat $CG/cgroup.controllers 2>/dev/null)"

cat > /tmp/conn.py <<'PY'
import socket, time, sys, json
port = int(sys.argv[1]); to = float(sys.argv[2])
s = socket.socket(); s.settimeout(to)
t0 = time.time()
try:
    s.connect(('127.0.0.1', port)); r = 'connected'
except Exception as e:
    r = type(e).__name__
dt = time.time() - t0
s.close()
print(json.dumps({"port": port, "result": r, "ms": round(dt * 1000, 1)}))
PY

echo $$ > "$CG/cgroup.procs"
python3 -m http.server 18080 --bind 127.0.0.1 >/tmp/httpd80.log 2>&1 &
SRV80=$!
python3 -m http.server 18081 --bind 127.0.0.1 >/tmp/httpd81.log 2>&1 &
SRV81=$!
sleep 1
echo "servers: 18080_pid=$SRV80 18081_pid=$SRV81 in=$(cat /proc/self/cgroup)"

echo "=== baseline (no bpf, both ports) ==="
python3 /tmp/conn.py 18080 1.0
python3 /tmp/conn.py 18081 1.0

echo "=== attach cgroup_skb egress: drop dport 18080 ==="
( ./loader net net_cgroup.bpf.o "$CG" 15 > /tmp/net_loader.out 2>&1 ) &
LP=$!
# tight probe loop to catch the moment enforcement starts
python3 - <<'PY'
import socket, time, json
def probe(port, to=0.3):
    s = socket.socket(); s.settimeout(to); t0 = time.time()
    try:
        s.connect(('127.0.0.1', port)); r = 'connected'
    except Exception as e:
        r = type(e).__name__
    dt = time.time() - t0; s.close(); return r, dt
start = time.time(); first_drop = None; res = []
while time.time() - start < 3.0:
    r80, d80 = probe(18080)
    if r80 != 'connected' and first_drop is None:
        first_drop = time.time() - start
    res.append(r80)
    time.sleep(0.05)
print(json.dumps({"attempts": len(res), "connected": res.count('connected'),
                  "failed": len(res) - res.count('connected'),
                  "first_failure_s": None if first_drop is None else round(first_drop, 3)}))
# control port must still work
r81, d81 = probe(18081, 0.5)
print(json.dumps({"control_port_18081": r81, "ms": round(d81 * 1000, 1)}))
PY
wait $LP 2>/dev/null
echo "=== loader output ==="
cat /tmp/net_loader.out
kill $SRV80 $SRV81 2>/dev/null
echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null
rmdir "$CG" 2>/dev/null && echo cgroup_removed || echo cgroup_busy
