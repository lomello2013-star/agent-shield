// Spike 15/37: cgroup/connect4 as an *observer* (returns 1 = allow), emitting connect
// events with the parent pid so process-tree correlation works for network sources too.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct net_evt {
    __u32 pid;
    __u32 daddr;
    __u32 ppid;
    __u32 pad;
    __u64 ts_ns;
    __u16 dport;
    __u16 family;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} net_events SEC(".maps");

SEC("cgroup/connect4")
int cg_connect_evt(struct bpf_sock_addr *ctx)
{
    struct net_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(),
                           real_parent, tgid);
    e.daddr = ctx->user_ip4;
    e.dport = ctx->user_port;
    e.family = ctx->family;
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&net_events, &e, sizeof(e), 0);
    return 1;   /* allow: observation only */
}

char LICENSE[] SEC("license") = "GPL";
