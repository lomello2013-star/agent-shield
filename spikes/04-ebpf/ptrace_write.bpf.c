// Spike 29: ptrace POKE* as a second memory-write path (T1055).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PTRACE_POKETEXT  4
#define PTRACE_POKEDATA  5
#define PTRACE_POKEUSR   6

struct ptrace_evt {
    __u32 pid;
    __u32 target;
    __u32 request;
    __u32 ppid;
    __u64 ts_ns;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ptrace_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ptrace")
int on_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 req = (__u32)ctx->args[0];
    if (req != PTRACE_POKETEXT && req != PTRACE_POKEDATA && req != PTRACE_POKEUSR)
        return 0;
    struct ptrace_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), real_parent, tgid);
    e.target = (__u32)ctx->args[1];
    e.request = req;
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&ptrace_events, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
