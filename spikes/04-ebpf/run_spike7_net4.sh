#!/bin/bash
# Spike 7 (Linux): per-process network deny via cgroup/connect4 eBPF hook.
set -u
SRC="$1"
WORK=/root/spike4
mkdir -p "$WORK"
cp "$SRC"/*.c "$WORK"/ 2>/dev/null
cd "$WORK" || exit 1
mount -t securityfs none /sys/kernel/security 2>/dev/null
echo "kernel=$(uname -r) active_lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)"

echo "=== compile net_connect4 ==="
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c net_connect4.bpf.c -o net_connect4.bpf.o 2>&1 | head -10
echo "obj_bytes=$(stat -c %s net_connect4.bpf.o 2>/dev/null || echo 0)"
gcc -O2 -o loader loader.c -lbpf -lz -lelf 2>&1 | head -10

CG=/sys/fs/cgroup/spike
mkdir -p "$CG"
echo "cgroup=$CG"

cat > /tmp/conn.py <<'PY'
import socket, time, sys, json
port = int(sys.argv[1]); to = float(sys.argv[2])
s = socket.socket(); s.settimeout(to)
t0 = time.time()
try:
    s.connect(('127.0.0.1', port)); r = 'connected'
except Exception as e:
    r = type(e).__name__ + ':' + str(getattr(e, 'errno', ''))
dt = time.time() - t0
s.close()
print(json.dumps({"port": port, "result": r, "ms": round(dt * 1000, 2)}))
PY

echo $$ > "$CG/cgroup.procs"
python3 -m http.server 18080 --bind 127.0.0.1 >/tmp/httpd80.log 2>&1 &
SRV80=$!
python3 -m http.server 18081 --bind 127.0.0.1 >/tmp/httpd81.log 2>&1 &
SRV81=$!
sleep 1
echo "self_cgroup=$(cat /proc/self/cgroup)"

echo "=== baseline: no bpf ==="
python3 /tmp/conn.py 18080 1.0
python3 /tmp/conn.py 18081 1.0

echo "=== attach cgroup/connect4 deny (port 18080) ==="
( ./loader net4 net_connect4.bpf.o "$CG" 10 > /tmp/net4_loader.out 2>&1 ) &
LP=$!
sleep 1.5
echo "=== during enforcement ==="
for i in 1 2 3 4 5; do python3 /tmp/conn.py 18080 0.5; done
echo "=== control: port 18081 must still connect ==="
python3 /tmp/conn.py 18081 0.5
echo "=== deny latency probe (10 attempts, measure EPERM round-trip) ==="
python3 - <<'PY'
import socket, time, json
lat = []
errs = []
for _ in range(10):
    s = socket.socket(); s.settimeout(0.5); t0 = time.time()
    try:
        s.connect(('127.0.0.1', 18080)); errs.append('connected')
    except Exception as e:
        errs.append(type(e).__name__)
    lat.append((time.time() - t0) * 1000); s.close()
lat.sort()
print(json.dumps({"n": len(lat), "errors": sorted(set(errs)),
                  "median_ms": round(lat[len(lat)//2], 3), "p95_ms": round(lat[int(len(lat)*0.95)-1], 3)}))
PY
wait $LP 2>/dev/null
echo "=== loader ==="; cat /tmp/net4_loader.out
kill $SRV80 $SRV81 2>/dev/null
echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null
rmdir "$CG" 2>/dev/null && echo cgroup_removed || echo cgroup_busy
