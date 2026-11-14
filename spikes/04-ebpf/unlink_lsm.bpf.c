// Canary delete sensor: LSM path_unlink emits the path being removed.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct unlink_evt {
    __u32 pid;
    __u32 ppid;
    __u64 ts_ns;
    char comm[16];
    char path[192];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} unlink_events SEC(".maps");

SEC("lsm/path_unlink")
int BPF_PROG(lsm_path_unlink, struct path *dir, struct dentry *dentry)
{
    struct unlink_evt e = {};
    (void)dir;

    const unsigned char *nm = BPF_CORE_READ(dentry, d_name.name);
    /* Name only: the canary rule matches the basename; avoids a variable-
     * offset stack write that the verifier rejects. */
    bpf_probe_read_kernel_str(e.path, sizeof(e.path), nm);

    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(),
                           real_parent, tgid);
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&unlink_events, &e, sizeof(e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
