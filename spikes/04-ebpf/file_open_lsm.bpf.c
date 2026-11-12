// Spike 4/14: LSM file_open hook, filtered to credential paths (low event volume).
// Uses bpf_d_path (allowed in LSM hooks) to get the real path; always allows.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct open_evt {
    __u32 pid;
    __u32 ppid;
    __u64 ts_ns;
    char comm[16];
    char path[192];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} open_events SEC(".maps");

static __always_inline int prefix(const char *p, const char *lit)
{
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (lit[i] == 0)
            return 1;
        if (p[i] != lit[i])
            return 0;
    }
    return 1;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open_cred, struct file *file)
{
    /* Always allow: this program only observes. Enforcement needs a signed policy. */
    struct open_evt e = {};
    long n = bpf_d_path((struct path *)&file->f_path, e.path, sizeof(e.path));
    if (n <= 0)
        return 0;
    if (!prefix(e.path, "/etc/shadow") && !prefix(e.path, "/etc/gshadow") &&
        !prefix(e.path, "/etc/sudoers") && !prefix(e.path, "/root/.ssh"))
        return 0;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    e.ppid = BPF_CORE_READ(t, real_parent, tgid);
    bpf_ringbuf_output(&open_events, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

