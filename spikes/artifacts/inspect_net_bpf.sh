cd /root/spike4
echo "=== does vmlinux.h define __sk_buff? ==="
grep -n "struct __sk_buff" vmlinux.h | head -3
echo "=== bpf_skb_load_bytes decl in bpf_helpers.h ==="
grep -rn "bpf_skb_load_bytes" /usr/include/bpf/bpf_helper_defs.h | head -3
echo "=== asm of first insns ==="
llvm-objdump -d --no-show-raw-insn net_cgroup.bpf.o 2>/dev/null | head -30
echo "=== source lines ==="
llvm-objdump -dS --no-show-raw-insn net_cgroup.bpf.o 2>/dev/null | sed -n '1,40p'
