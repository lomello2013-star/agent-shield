// AIDefender Linux kernel enforcement (BPF LSM).
//
// Denies:
//   * exec of paths/prefixes listed in deny_exec;
//   * writable opens of paths/prefixes listed in deny_write.
//
// Policy is a set of FNV-1a hashes of directory prefixes/exact paths. The BPF
// program hashes every path prefix at '/' boundaries, so a policy entry
// "/tmp/" covers "/tmp/evil" without a per-file list.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH 128

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} deny_exec SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} deny_write SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} mode SEC(".maps");

struct guard_evt {
    __u32 pid;
    __u32 ppid;
    __u64 ts_ns;
    __u8 kind;              // 1=exec, 2=write
    __u8 denied;
    char comm[16];
    char path[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline __u64 fnv1a(const char *s, int len)
{
    __u64 h = 1469598103934665603ULL;
#pragma unroll
    for (int i = 0; i < MAX_PATH; i++) {
        if (i >= len)
            break;
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static __always_inline int check_prefixes(void *map, const char *path, int len)
{
    __u64 h = 1469598103934665603ULL;
#pragma unroll
    for (int i = 0; i < MAX_PATH; i++) {
        if (i >= len)
            break;
        unsigned char c = path[i];
        h ^= c;
        h *= 1099511628211ULL;
        if (c == '/' || i == len - 1) {
            __u8 *v = bpf_map_lookup_elem(map, &h);
            if (v)
                return 1;
        }
    }
    /* exact path hash (for files that don't end with '/') */
    __u64 exact = fnv1a(path, len);
    return bpf_map_lookup_elem(map, &exact) != 0;
}

static __always_inline void emit(__u8 kind, __u8 denied, const char *path, int len)
{
    struct guard_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ts_ns = bpf_ktime_get_ns();
    e.kind = kind;
    e.denied = denied;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    if (len > MAX_PATH - 1)
        len = MAX_PATH - 1;
    if (path)
        bpf_probe_read_kernel_str(e.path, sizeof(e.path), path);
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
}

static __always_inline int active(void)
{
    __u32 key = 0;
    __u32 *m = bpf_map_lookup_elem(&mode, &key);
    return m && *m;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(aidf_exec, struct linux_binprm *bprm)
{
    char path[MAX_PATH] = {};
    long n = bpf_d_path(&bprm->file->f_path, path, sizeof(path));
    if (n <= 0)
        return 0;
    if (!check_prefixes(&deny_exec, path, (int)n))
        return 0;
    int enforce = active();
    emit(1, enforce, path, (int)n);
    return enforce ? -13 : 0;      // -EACCES
}

SEC("lsm/file_open")
int BPF_PROG(aidf_open, struct file *file)
{
    unsigned int flags = BPF_CORE_READ(file, f_flags);
    if ((flags & 0x3) == 0)        // O_RDONLY
        return 0;
    char path[MAX_PATH] = {};
    long n = bpf_d_path(&file->f_path, path, sizeof(path));
    if (n <= 0)
        return 0;
    if (!check_prefixes(&deny_write, path, (int)n))
        return 0;
    int enforce = active();
    emit(2, enforce, path, (int)n);
    return enforce ? -13 : 0;
}

char LICENSE[] SEC("license") = "GPL";

