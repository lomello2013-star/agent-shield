// Spike 4/7: per-cgroup egress packet drop by TCP dport (cgroup_skb, plain SEC signature).
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

SEC("cgroup_skb/egress")
int cg_egress(struct __sk_buff *skb)
{
    struct iphdr ip;
    struct tcphdr th;
    __u32 ihl;

    if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
        return 1;
    if (ip.version != 4 || ip.protocol != IPPROTO_TCP)
        return 1;
    ihl = ip.ihl * 4;
    if (ihl < 20)
        return 1;
    if (bpf_skb_load_bytes(skb, ihl, &th, sizeof(th)) < 0)
        return 1;
    if (th.dest == bpf_htons(TARGET_PORT)) {
        bump(0);
        return 0; /* DROP */
    }
    bump(1);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
