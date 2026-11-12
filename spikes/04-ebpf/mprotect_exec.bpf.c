// Spike 31/37: mprotect adding PROT_EXEC to anonymous memory (JIT/injection primitive).
// Emits exe path components from the kernel for provenance-aware correlation.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PROT_EXEC 0x4
#define VM_EXEC   0x00000004
#define MAX_PARTS 8
#define PART_LEN 16

struct exe_field {
    __u32 n;
    char parts[MAX_PARTS][PART_LEN];
};

struct mprot_evt {
    __u32 pid;
    __u32 anon;
    __u32 ppid;
    __u32 pad;
    __u64 len;
    __u64 ts_ns;
    struct exe_field exe;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} mprot_events SEC(".maps");

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
            break;
        d = parent;
    }
}

SEC("lsm/file_mprotect")
int BPF_PROG(lsm_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot)
{
    if (!(prot & PROT_EXEC))
        return 0;
    unsigned long flags = BPF_CORE_READ(vma, vm_flags);
    if (flags & VM_EXEC)
        return 0;

    struct mprot_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), real_parent, tgid);
    e.anon = BPF_CORE_READ(vma, vm_file) ? 0 : 1;
    e.len = (__u64)BPF_CORE_READ(vma, vm_end) - (__u64)BPF_CORE_READ(vma, vm_start);
    e.ts_ns = bpf_ktime_get_ns();
    read_exe(&e.exe);
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&mprot_events, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
