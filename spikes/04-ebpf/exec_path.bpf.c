// Spike 4/12: exec tracepoint with the real binary path (for Linux rules like /tmp exec).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct exec_evt {
    __u32 pid;
    __u32 ppid;
    __u64 ts_ns;
    char comm[16];
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} exec_events SEC(".maps");

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec_path, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    struct exec_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = BPF_CORE_READ(p, real_parent, pid);
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    const char *fn = BPF_CORE_READ(bprm, filename);
    if (fn)
        bpf_probe_read_kernel_str(&e.filename, sizeof(e.filename), fn);
    bpf_ringbuf_output(&exec_events, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
