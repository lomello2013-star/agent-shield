// DNS query sensor: captures sendto payloads; user space extracts qname.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct dns_evt {
    __u32 pid;
    __u32 ppid;
    __u64 ts_ns;
    __u32 len;
    char comm[16];
    __u8 payload[96];
};

struct sys_enter_ctx {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
    long id;
    unsigned long args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} dns_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_sendto")
int on_dns(struct sys_enter_ctx *ctx)
{
    __u64 len = (__u64)ctx->args[2];
    if (len < 12 || len > 4096)
        return 0;

    struct dns_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(),
                           real_parent, tgid);
    e.ts_ns = bpf_ktime_get_ns();
    e.len = (__u32)len;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user(e.payload, sizeof(e.payload), (const void *)ctx->args[1]);
    bpf_ringbuf_output(&dns_events, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
