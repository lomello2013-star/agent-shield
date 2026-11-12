// Spike 30: writing through /proc/<pid>/mem (third T1055 path).
// LSM file_open sees the path; match a short "/proc/.../mem" path (bounded scan, NUL
// terminated) and emit whether the file was opened for writing.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct proc_mem_evt {
    __u32 pid;
    __u32 writable;
    __u32 ppid;
    __u64 ts_ns;
    char comm[16];
    char path[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} procmem_events SEC(".maps");

static __always_inline int is_proc_mem(const char *p, long n)
{
    if (n < 8 || n > 48)
        return 0;
    if (p[0] != '/' || p[1] != 'p' || p[2] != 'r' || p[3] != 'o' ||
        p[4] != 'c' || p[5] != '/')
        return 0;
#pragma unroll
    for (int i = 6; i < 44; i++) {
        if (p[i] == '/' && p[i + 1] == 'm' && p[i + 2] == 'e' && p[i + 3] == 'm' &&
            p[i + 4] == '\0')
            return 1;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_proc_mem, struct file *file)
{
    struct proc_mem_evt e = {};
    long n = bpf_d_path((struct path *)&file->f_path, e.path, sizeof(e.path));
    if (n <= 0)
        return 0;
    if (!is_proc_mem(e.path, n))
        return 0;

    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), real_parent, tgid);
    e.writable = (BPF_CORE_READ(file, f_flags) & 0x3) ? 1 : 0;   /* O_WRONLY|O_RDWR */
    e.ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&procmem_events, &e, sizeof(e), 0);
    return 0;   /* always allow: observation only */
}

char LICENSE[] SEC("license") = "GPL";
