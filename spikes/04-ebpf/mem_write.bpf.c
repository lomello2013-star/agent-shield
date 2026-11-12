// Spike 28/37: process_vm_writev as a real cross-process memory-write source (T1055).
// Emits the exe path components read from the kernel (dentry walk), so provenance does
// not depend on userspace /proc resolution.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PARTS 8
#define PART_LEN 16

struct exe_field {
    __u32 n;
    char parts[MAX_PARTS][PART_LEN];
};

struct mem_evt {
    __u32 pid;
    __u32 target;
    __u32 ppid;
    __u32 pad;
    __u64 ts_ns;
    __u64 bytes;
    struct exe_field exe;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} mem_events SEC(".maps");

static __always_inline void read_exe(struct exe_field *out)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct file *f = BPF_CORE_READ(t, mm, exe_file);
    if (!f)
        return;
    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
#pragma unroll
    for (int i = 0; i < MAX_PARTS; i++) {
        if (!d)
            break;
        const unsigned char *name = BPF_CORE_READ(d, d_name.name);
        if (!name)
            break;
        bpf_probe_read_kernel_str(&out->parts[i], PART_LEN, name);
        out->n = i + 1;
        struct dentry *parent = BPF_CORE_READ(d, d_parent);
        if (parent == d)
            break;                 /* reached the root */
        d = parent;
    }
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int on_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    struct mem_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.target = (__u32)ctx->args[0];
    e.ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), real_parent, tgid);
    e.bytes = (__u64)ctx->args[4];
    e.ts_ns = bpf_ktime_get_ns();
    read_exe(&e.exe);
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&mem_events, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
