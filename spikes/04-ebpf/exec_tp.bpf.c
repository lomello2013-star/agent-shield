// Spike 4: tracepoint + CO-RE probe (WSL2 kernel 6.18, BTF present)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct exec_evt {
    __u32 pid;
    __u32 ppid;
    __u64 ts_ns;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} exec_count SEC(".maps");

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    struct exec_evt e = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 key = 0;
    __u64 *cnt;

    e.pid = pid;
    e.ppid = BPF_CORE_READ(p, real_parent, tgid);   /* CO-RE relocation */
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&exec_events, &e, sizeof(e), 0);

    cnt = bpf_map_lookup_elem(&exec_count, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    else {
        __u64 one = 1;
        bpf_map_update_elem(&exec_count, &key, &one, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
