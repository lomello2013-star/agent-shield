// AIDefender Linux kernel enforcement (BPF LSM).
//
// Denies:
//   * exec from writable directories (static, low-verifier-cost prefixes);
//   * writable opens of exact protected files (policy map).
//
// Prefix hashing every path character was rejected by the verifier as too large
// (1M insn limit). Static `bpf_strncmp` for the four exec prefixes + exact-path
// map for protected files keeps the program small and auditable.
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
} deny_write SEC(".maps");

struct inode_key {
    __u64 dev;
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct inode_key);
    __type(value, __u8);
} deny_inode SEC(".maps");

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
    __u64 hash;
    __u8 kind;
    __u8 denied;
    char comm[16];
    char path[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int exec_denied(const char *p)
{
    return !bpf_strncmp(p, 5, "/tmp/") ||
           !bpf_strncmp(p, 9, "/var/tmp/") ||
           !bpf_strncmp(p, 9, "/dev/shm/") ||
           !bpf_strncmp(p, 10, "/run/user/");
}

static __always_inline void emit(__u8 kind, __u8 denied, const char *path, int len,
                                 __u64 hash)
{
    struct guard_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ts_ns = bpf_ktime_get_ns();
    e.hash = hash;
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

static __always_inline __u64 path_hash(const char *p)
{
    __u64 h = 1469598103934665603ULL;
#pragma unroll
    for (int i = 0; i < MAX_PATH; i++) {
        char c = p[i];
        if (!c)
            break;
        h ^= (unsigned char)c;
        h *= 1099511628211ULL;
    }
    return h;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(aidf_exec, struct linux_binprm *bprm)
{
    char path[MAX_PATH] = {};
    long n = bpf_d_path(&bprm->file->f_path, path, sizeof(path));
    if (n <= 0 || !exec_denied(path))
        return 0;
    int enforce = active();
    emit(1, enforce, path, (int)n, 0);
    return enforce ? -13 : 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(aidf_inode, struct inode *inode, int mask)
{
    if ((mask & 0x2) == 0)       /* MAY_WRITE */
        return 0;
    struct inode_key k = {
        .dev = BPF_CORE_READ(inode, i_sb, s_dev),
        .ino = BPF_CORE_READ(inode, i_ino),
    };
    if (!bpf_map_lookup_elem(&deny_inode, &k))
        return 0;
    int enforce = active();
    emit(2, enforce, "inode", 5, 0);
    return enforce ? -13 : 0;
}

SEC("lsm/file_open")
int BPF_PROG(aidf_open, struct file *file)
{
    unsigned int flags = BPF_CORE_READ(file, f_flags);
    if ((flags & 0x3) == 0)
        return 0;
    char path[MAX_PATH] = {};
    long n = bpf_d_path(&file->f_path, path, sizeof(path));
    if (n <= 0)
        return 0;
    __u64 h = path_hash(path);
    if (!bpf_map_lookup_elem(&deny_write, &h))
        return 0;
    int enforce = active();
    emit(2, enforce, path, (int)n, h);
    return enforce ? -13 : 0;
}

char LICENSE[] SEC("license") = "GPL";

