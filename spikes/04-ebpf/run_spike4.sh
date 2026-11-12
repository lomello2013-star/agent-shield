#!/bin/bash
# Spike 4: build CO-RE objects against kernel BTF and exercise them.
set -u
SRC="$1"
WORK=/root/spike4
mkdir -p "$WORK"
cp "$SRC"/*.c "$WORK"/ 2>/dev/null
cd "$WORK" || exit 1

echo "=== kernel ==="
uname -r
echo "btf_size=$(stat -c %s /sys/kernel/btf/vmlinux)"
echo "active_lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)"

echo "=== vmlinux.h generation (bpftool btf dump) ==="
t0=$(date +%s%N)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>btf.err
t1=$(date +%s%N)
echo "vmlinux_h_bytes=$(stat -c %s vmlinux.h) gen_ms=$(( (t1 - t0) / 1000000 ))"
head -3 btf.err

echo "=== compile (clang -target bpf, CO-RE -g) ==="
for f in exec_tp.bpf net_cgroup.bpf open_lsm.bpf; do
  t0=$(date +%s%N)
  clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c "$f.c" -o "$f.o" 2> "$$_$f.err"
  rc=$?
  t1=$(date +%s%N)
  echo "$f rc=$rc ms=$(( (t1 - t0) / 1000000 )) obj_bytes=$(stat -c %s "$f.o" 2>/dev/null || echo 0)"
  head -5 "$$_$f.err"
done

echo "=== loader build ==="
gcc -O2 -o loader loader.c -lbpf -lz -lelf 2>&1 | head -20
ls -la loader 2>/dev/null | awk '{print "loader_bytes="$5}'

echo "=== BTF sections in objects (CO-RE proof) ==="
for o in exec_tp.bpf.o net_cgroup.bpf.o open_lsm.bpf.o; do
  echo "$o: $(readelf -S "$o" 2>/dev/null | grep -cE '\.BTF|\.rel') sections, relocs=$(readelf -r "$o" 2>/dev/null | grep -c 'BTF')"
done

echo "=== run: tracepoint (exec) ==="
./loader exec exec_tp.bpf.o 40 2>&1
echo "=== run: LSM hook (file_open) ==="
./loader lsm open_lsm.bpf.o 100 2>&1
