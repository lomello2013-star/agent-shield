// Loader for aidf_enforce.bpf.o (BPF LSM prevention).
// Usage: aidf-enforce <audit|enforce> <bpf.o> <policy.txt>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PATH 256

static volatile sig_atomic_t stop;
static void on_sig(int sig) { (void)sig; stop = 1; }

static uint64_t fnv1a(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

static int lookup_mode(const char *s)
{
    if (strcmp(s, "enforce") == 0) return 1;
    if (strcmp(s, "audit") == 0) return 0;
    return -1;
}

static int add_path(int fd, const char *path)
{
    uint64_t key = fnv1a(path);
    uint8_t one = 1;
    if (bpf_map_update_elem(fd, &key, &one, BPF_ANY) != 0) {
        fprintf(stderr, "policy: cannot add %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int on_event(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    const struct {
        uint32_t pid, ppid;
        uint64_t ts_ns;
        uint8_t kind, denied;
        char comm[16];
        char path[MAX_PATH];
    } *e = data;
    printf("{\"kind\":\"%s\",\"pid\":%u,\"ppid\":%u,\"comm\":\"%s\",\"path\":\"%s\",\"denied\":%s}\n",
           e->kind == 1 ? "exec" : "write", e->pid, e->ppid, e->comm, e->path,
           e->denied ? "true" : "false");
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <audit|enforce> <aidf_enforce.bpf.o> <policy.txt>\n", argv[0]);
        return 2;
    }
    int mode_val = lookup_mode(argv[1]);
    if (mode_val < 0) { fprintf(stderr, "bad mode\n"); return 2; }

    struct bpf_object *obj = bpf_object__open_file(argv[2], NULL);
    if (!obj) { fprintf(stderr, "open: %s\n", strerror(errno)); return 1; }
    fprintf(stderr, "debug: object opened\n");
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    fprintf(stderr, "debug: object loaded\n");

    int exec_fd = bpf_object__find_map_fd_by_name(obj, "deny_exec");
    int write_fd = bpf_object__find_map_fd_by_name(obj, "deny_write");
    int mode_fd = bpf_object__find_map_fd_by_name(obj, "mode");
    if (exec_fd < 0 || write_fd < 0 || mode_fd < 0) {
        fprintf(stderr, "maps missing\n"); return 1;
    }
    uint32_t zero = 0, mode = (uint32_t)mode_val;
    if (bpf_map_update_elem(mode_fd, &zero, &mode, BPF_ANY) != 0) {
        fprintf(stderr, "mode map: %s\n", strerror(errno)); return 1;
    }

    FILE *fp = fopen(argv[3], "r");
    if (!fp) { fprintf(stderr, "policy: %s\n", strerror(errno)); return 1; }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0] || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        const char *kind = line, *path = eq + 1;
        if (strcmp(kind, "exec") == 0) {
            if (add_path(exec_fd, path) != 0) return 1;
        } else if (strcmp(kind, "write") == 0) {
            if (add_path(write_fd, path) != 0) return 1;
        }
    }
    fclose(fp);

    struct bpf_program *exec_prog = bpf_object__find_program_by_name(obj, "aidf_exec");
    struct bpf_program *open_prog = bpf_object__find_program_by_name(obj, "aidf_open");
    if (!exec_prog || !open_prog) { fprintf(stderr, "programs missing\n"); return 1; }
    struct bpf_link *exec_link = bpf_program__attach_lsm(exec_prog);
    struct bpf_link *open_link = bpf_program__attach_lsm(open_prog);
    if (!exec_link || !open_link) {
        fprintf(stderr, "attach_lsm failed: %s (is BPF LSM enabled?)\n", strerror(errno));
        if (exec_link) bpf_link__destroy(exec_link);
        if (open_link) bpf_link__destroy(open_link);
        bpf_object__close(obj);
        return 1;
    }

    int events_fd = bpf_object__find_map_fd_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(events_fd, on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ringbuf: %s\n", strerror(errno)); return 1; }
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    printf("{\"kind\":\"guard_ready\",\"engine\":\"ebpf-lsm\",\"mode\":\"%s\"}\n", argv[1]);
    fflush(stdout);
    while (!stop) ring_buffer__poll(rb, 500);
    ring_buffer__free(rb);
    bpf_link__destroy(exec_link);
    bpf_link__destroy(open_link);
    bpf_object__close(obj);
    return 0;
}
