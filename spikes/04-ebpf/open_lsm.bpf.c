// Spike 4: LSM hook program (BPF LSM). Returns 0 = allow; counts file_open calls.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} lsm_count SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&lsm_count, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&lsm_count, &key, &one, BPF_ANY);
    }
    /* always allow: this spike measures availability, not enforcement */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
