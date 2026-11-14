// Large sendto sensor: emits syscalls with >=1 MB payload for exfil correlation.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct send_evt {
    __u32 pid;
    __u32 ppid;
    __u64 ts_ns;
    __u64 bytes;
    char comm[16];
};

/* sys_enter tracepoint context (trace_entry + id + args[6]); BTF does not
 * expose trace_event_raw_sys_enter on this kernel. */
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
} send_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_sendto")
int on_sendto(struct sys_enter_ctx *ctx)
{
    __u64 len = (__u64)ctx->args[2];
    if (len < 1000000ULL)
        return 0;

    struct send_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(),
                           real_parent, tgid);
    e.ts_ns = bpf_ktime_get_ns();
    e.bytes = len;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&send_events, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
