#!/usr/bin/env bash
# Build Linux eBPF objects + loader from the spike sources (not committed).
#
# Requires: clang, bpftool, gcc, libbpf headers/lib, zlib, libelf.
#   sudo bash scripts/build_linux_ebpf.sh [OUT_DIR]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/spikes/04-ebpf"
OUT=${1:-"$ROOT/dist/ebpf"}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

command -v clang >/dev/null || { echo "clang missing" >&2; exit 2; }
command -v bpftool >/dev/null || { echo "bpftool missing" >&2; exit 2; }
command -v gcc >/dev/null || { echo "gcc missing" >&2; exit 2; }
[ -r /sys/kernel/btf/vmlinux ] || { echo "kernel BTF missing" >&2; exit 2; }

cp "$SRC"/*.c "$WORK"/
cd "$WORK"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
for f in "$WORK"/*.bpf.c; do
    name=$(basename "$f" .c)
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I"$WORK" -c "$f" -o "$name.o"
done
gcc -O2 -o loader loader.c -lbpf -lz -lelf
gcc -O2 -o aidf-enforce aidf_enforce_loader.c -lbpf -lz -lelf

mkdir -p "$OUT"
cp loader "$OUT"/
cp aidf-enforce "$OUT"/
cp ./*.bpf.o "$OUT"/
echo "built $(find "$OUT" -maxdepth 1 -name '*.bpf.o' | wc -l) objects + loader in $OUT"
echo "next: python3 scripts/linux_object_manifest.py --src $OUT && python3 scripts/sign_linux_manifest.py"
