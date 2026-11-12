// Spike 7 (Linux): per-cgroup/per-process network deny via cgroup/connect4 hook.
// Plain SEC signature (BPF_PROG is for tracing programs and adds ctx indirection).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TARGET_PORT 18080

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} net_stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&net_stats, &idx);
    if (v) {
        __sync_fetch_and_add(v, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&net_stats, &idx, &one, BPF_ANY);
    }
}

SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
    if (bpf_ntohs(ctx->user_port) == TARGET_PORT) {
        bump(0);       /* denied */
        return 0;      /* deny -> connect() fails with EPERM */
    }
    bump(1);           /* allowed */
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
