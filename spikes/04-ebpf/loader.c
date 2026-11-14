// Spike 4 loader: loads the CO-RE objects above and measures real behaviour.
// Usage: loader exec|lsm|net <obj> [cgroup_path] [n]
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct exe_field {
    unsigned int n;
    char parts[8][16];
};

static void render_exe(const struct exe_field *e, char *out, int sz)
{
    int len = 0;
    out[0] = 0;
    for (int i = (int)e->n - 1; i >= 0; i--) {
        const char *p = e->parts[i];
        if (strcmp(p, "/") == 0) {
            if (len == 0 && sz > 1) { out[len++] = '/'; out[len] = 0; }
            continue;
        }
        if (len > 0 && out[len - 1] != '/' && len < sz - 1) out[len++] = '/';
        for (int j = 0; p[j] && len < sz - 1; j++) out[len++] = p[j];
        out[len] = 0;
    }
}


struct exec_evt {
    unsigned int pid;
    unsigned int ppid;
    unsigned long long ts_ns;
    char comm[16];
};

struct mprot_evt {
    unsigned int pid;
    unsigned int anon;
    unsigned int ppid;
    unsigned int pad;
    unsigned long long len;
    unsigned long long ts_ns;
    struct exe_field exe;
    char comm[16];
};

struct proc_mem_evt {
    unsigned int pid;
    unsigned int writable;
    unsigned int ppid;
    unsigned int pad;
    unsigned long long ts_ns;
    char comm[16];
    char path[128];
};

struct ptrace_evt {
    unsigned int pid;
    unsigned int target;
    unsigned int request;
    unsigned int ppid;
    unsigned long long ts_ns;
    char comm[16];
};


struct mem_evt {
    unsigned int pid;
    unsigned int target;
    unsigned int ppid;
    unsigned int pad;
    unsigned long long ts_ns;
    unsigned long long bytes;
    struct exe_field exe;
    char comm[16];
};

struct net_evt {
    unsigned int pid;
    unsigned int daddr;
    unsigned int ppid;
    unsigned int pad;
    unsigned long long ts_ns;
    unsigned short dport;
    unsigned short family;
    char comm[16];
};

struct open_evt {
    unsigned int pid;
    unsigned int ppid;
    unsigned long long ts_ns;
    char comm[16];
    char path[192];
    unsigned int writable;
};

struct unlink_evt {
    unsigned int pid;
    unsigned int ppid;
    unsigned long long ts_ns;
    char comm[16];
    char path[192];
};

struct send_evt {
    unsigned int pid;
    unsigned int ppid;
    unsigned long long ts_ns;
    unsigned long long bytes;
    char comm[16];
};

struct exec_path_evt {
    unsigned int pid;
    unsigned int ppid;
    unsigned long long ts_ns;
    char comm[16];
    char filename[128];
};

static int got = 0;
static long long lat_max = 0;
static long long lat_sum = 0;
static int lat_n = 0;

static int on_event(void *ctx, void *data, size_t sz)
{
    struct exec_evt *e = data;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long long now = (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    long long lat = (long long)(now - e->ts_ns);
    if (lat < 0)
        lat = 0;
    got++;
    lat_sum += lat;
    if (lat > lat_max)
        lat_max = lat;
    lat_n++;
    return 0;
}

static void ipv4_str(unsigned int addr, char *out, size_t n)
{
    unsigned char *b = (unsigned char *)&addr;
    snprintf(out, n, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static int on_mprot_json(void *ctx, void *data, size_t sz)
{
    struct mprot_evt *e = data;
    char exe[128];
    render_exe(&e->exe, exe, sizeof(exe));
    printf("{\"pid\":%u,\"anon\":%u,\"ppid\":%u,\"len\":%llu,\"ts_ns\":%llu,\"exe\":\"%s\",\"comm\":\"%s\"}\n",
           e->pid, e->anon, e->ppid, e->len, (unsigned long long)e->ts_ns,
           exe, e->comm);
    fflush(stdout);
    got++;
    return 0;
}

static int on_procmem_json(void *ctx, void *data, size_t sz)
{
    struct proc_mem_evt *e = data;
    printf("{\"pid\":%u,\"writable\":%u,\"ppid\":%u,\"path\":\"%s\",\"ts_ns\":%llu,\"comm\":\"%s\"}\n",
           e->pid, e->writable, e->ppid, e->path, (unsigned long long)e->ts_ns, e->comm);
    fflush(stdout);
    got++;
    return 0;
}

static int on_ptrace_json(void *ctx, void *data, size_t sz)
{
    struct ptrace_evt *e = data;
    printf("{\"pid\":%u,\"target\":%u,\"request\":%u,\"ppid\":%u,\"ts_ns\":%llu,\"comm\":\"%s\"}\n",
           e->pid, e->target, e->request, e->ppid, (unsigned long long)e->ts_ns, e->comm);
    fflush(stdout);
    got++;
    return 0;
}

static int on_mem_json(void *ctx, void *data, size_t sz)
{
    struct mem_evt *e = data;
    char exe[128];
    render_exe(&e->exe, exe, sizeof(exe));
    printf("{\"pid\":%u,\"target\":%u,\"ppid\":%u,\"bytes\":%llu,\"ts_ns\":%llu,\"exe\":\"%s\",\"comm\":\"%s\"}\n",
           e->pid, e->target, e->ppid, e->bytes, (unsigned long long)e->ts_ns,
           exe, e->comm);
    fflush(stdout);
    got++;
    return 0;
}

static int on_net_json(void *ctx, void *data, size_t sz)
{
    struct net_evt *e = data;
    char ip[32];
    ipv4_str(e->daddr, ip, sizeof(ip));
    printf("{\"pid\":%u,\"ppid\":%u,\"comm\":\"%s\",\"daddr\":\"%s\",\"dport\":%u,"
           "\"ts_ns\":%llu}\n",
           e->pid, e->ppid, e->comm, ip, (unsigned)ntohs(e->dport),
           (unsigned long long)e->ts_ns);
    fflush(stdout);
    got++;
    return 0;
}

static int on_open_json(void *ctx, void *data, size_t sz)
{
    struct open_evt *e = data;
    printf("{\"pid\":%u,\"ppid\":%u,\"ts_ns\":%llu,\"comm\":\"%s\",\"path\":\"%s\",\"writable\":%u}\n",
           e->pid, e->ppid, (unsigned long long)e->ts_ns, e->comm, e->path,
           e->writable);
    fflush(stdout);
    got++;
    return 0;
}

static int on_sendto_json(void *ctx, void *data, size_t sz)
{
    struct send_evt *e = data;
    printf("{\"op\":\"sendto\",\"pid\":%u,\"ppid\":%u,\"ts_ns\":%llu,\"bytes\":%llu,\"comm\":\"%s\"}\n",
           e->pid, e->ppid, (unsigned long long)e->ts_ns,
           (unsigned long long)e->bytes, e->comm);
    fflush(stdout);
    got++;
    return 0;
}

static int on_unlink_json(void *ctx, void *data, size_t sz)
{
    struct unlink_evt *e = data;
    printf("{\"op\":\"unlink\",\"pid\":%u,\"ppid\":%u,\"ts_ns\":%llu,\"comm\":\"%s\",\"path\":\"%s\"}\n",
           e->pid, e->ppid, (unsigned long long)e->ts_ns, e->comm, e->path);
    fflush(stdout);
    got++;
    return 0;
}

static int on_event_json(void *ctx, void *data, size_t sz)
{
    struct exec_path_evt *e = data;
    printf("{\"pid\":%u,\"ppid\":%u,\"ts_ns\":%llu,\"comm\":\"%s\",\"filename\":\"%s\"}\n",
           e->pid, e->ppid, (unsigned long long)e->ts_ns, e->comm, e->filename);
    fflush(stdout);
    got++;
    return 0;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s exec|lsm|net <obj> [cgroup_path] [n]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *path = argv[2];
    int n = argc >= 5 ? atoi(argv[4]) : 20;

    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj) {
        printf("{\"error\":\"open\",\"errno\":%d}\n", errno);
        return 1;
    }
    double t0 = now_ms();
    int err = bpf_object__load(obj);
    double load_ms = now_ms() - t0;
    if (err) {
        printf("{\"mode\":\"%s\",\"error\":\"load\",\"errno\":%d,\"load_ms\":%.2f}\n",
               mode, errno, load_ms);
        bpf_object__close(obj);
        return 1;
    }

    if (strcmp(mode, "exec") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "on_exec");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            printf("{\"mode\":\"exec\",\"error\":\"attach\",\"errno\":%d,\"load_ms\":%.2f}\n", errno, load_ms);
            return 1;
        }
        int mfd = bpf_object__find_map_fd_by_name(obj, "exec_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_event, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        for (int i = 0; i < n; i++) {
            pid_t p = fork();
            if (p == 0) { execl("/bin/true", "true", (char *)NULL); _exit(127); }
            waitpid(p, NULL, 0);
            ring_buffer__poll(rb, 300);
        }
        /* drain */
        for (int i = 0; i < 5; i++) ring_buffer__poll(rb, 50);
        int cfd = bpf_object__find_map_fd_by_name(obj, "exec_count");
        unsigned int key = 0;
        unsigned long long cnt = 0;
        bpf_map_lookup_elem(cfd, &key, &cnt);
        printf("{\"mode\":\"exec\",\"load_ms\":%.2f,\"launched\":%d,\"events\":%d,\"map_count\":%llu,"
               "\"lat_avg_us\":%.1f,\"lat_max_us\":%.1f}\n",
               load_ms, n, got, cnt, lat_n ? (lat_sum / 1000.0 / lat_n) : 0.0, lat_max / 1000.0);
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "lsm") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "lsm_file_open");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (!link) {
            printf("{\"mode\":\"lsm\",\"error\":\"attach_lsm\",\"errno\":%d,\"load_ms\":%.2f}\n", errno, load_ms);
            return 1;
        }
        int opens = 0;
        for (int i = 0; i < n; i++) {
            int fd = open("/etc/hostname", O_RDONLY);
            if (fd >= 0) { close(fd); opens++; }
        }
        int cfd = bpf_object__find_map_fd_by_name(obj, "lsm_count");
        unsigned int key = 0;
        unsigned long long cnt = 0;
        bpf_map_lookup_elem(cfd, &key, &cnt);
        printf("{\"mode\":\"lsm\",\"load_ms\":%.2f,\"opens\":%d,\"hook_hits\":%llu}\n", load_ms, opens, cnt);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "net4") == 0) {
        const char *cgpath = argc >= 4 ? argv[3] : "/sys/fs/cgroup/spike";
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "cg_connect4");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        int cgfd = open(cgpath, O_RDONLY | O_DIRECTORY);
        if (cgfd < 0) { printf("{\"mode\":\"net4\",\"error\":\"cgroup_open\",\"errno\":%d}\n", errno); return 1; }
        struct bpf_link *link = bpf_program__attach_cgroup(prog, cgfd);
        if (!link) {
            printf("{\"mode\":\"net4\",\"error\":\"attach_cgroup\",\"errno\":%d,\"load_ms\":%.2f}\n", errno, load_ms);
            return 1;
        }
        printf("{\"mode\":\"net4\",\"attach\":\"ok\",\"load_ms\":%.2f}\n", load_ms);
        fflush(stdout);
        sleep(n > 0 ? n : 5);
        int sfd = bpf_object__find_map_fd_by_name(obj, "net_stats");
        unsigned int k0 = 0, k1 = 1;
        unsigned long long denied = 0, allowed = 0;
        bpf_map_lookup_elem(sfd, &k0, &denied);
        bpf_map_lookup_elem(sfd, &k1, &allowed);
        printf("{\"mode\":\"net4\",\"stats_denied\":%llu,\"stats_allowed\":%llu}\n", denied, allowed);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "on_exec_path");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) { printf("{\"error\":\"attach\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "exec_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_event_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        int limit = argc >= 4 ? atoi(argv[3]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream_open") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "lsm_file_open_cred");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (!link) { printf("{\"error\":\"attach_lsm\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "open_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_open_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        printf("{\"ready\":true}\n");
        fflush(stdout);
        int limit = argc >= 4 ? atoi(argv[3]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream_sendto") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "on_sendto");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) { printf("{\"error\":\"attach\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "send_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_sendto_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        printf("{\"ready\":true}\n");
        fflush(stdout);
        int limit = argc >= 4 ? atoi(argv[3]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream_unlink") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "lsm_path_unlink");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (!link) { printf("{\"error\":\"attach_lsm\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "unlink_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_unlink_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        printf("{\"ready\":true}\n");
        fflush(stdout);
        int limit = argc >= 4 ? atoi(argv[3]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream_mprotect") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "lsm_mprotect");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (!link) { printf("{\"error\":\"attach_lsm\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "mprot_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_mprot_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        printf("{\"ready\":true}\n");
        fflush(stdout);
        int limit = argc >= 4 ? atoi(argv[3]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream_procmem") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "lsm_proc_mem");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach_lsm(prog);
        if (!link) { printf("{\"error\":\"attach_lsm\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "procmem_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_procmem_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        printf("{\"ready\":true}\n");
        fflush(stdout);
        int limit = argc >= 4 ? atoi(argv[3]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream_ptrace") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "on_ptrace");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) { printf("{\"error\":\"attach\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "ptrace_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_ptrace_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        printf("{\"ready\":true}\n");
        fflush(stdout);
        int limit = argc >= 4 ? atoi(argv[3]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream_mem") == 0) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "on_vm_writev");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) { printf("{\"error\":\"attach\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "mem_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_mem_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        printf("{\"ready\":true}\n");
        fflush(stdout);
        int limit = argc >= 4 ? atoi(argv[3]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "stream_net") == 0) {
        const char *cgpath = argc >= 4 ? argv[3] : "/sys/fs/cgroup/aidf";
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "cg_connect_evt");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        int cgfd = open(cgpath, O_RDONLY | O_DIRECTORY);
        if (cgfd < 0) { printf("{\"error\":\"cgroup_open\",\"errno\":%d}\n", errno); return 1; }
        struct bpf_link *link = bpf_program__attach_cgroup(prog, cgfd);
        if (!link) { printf("{\"error\":\"attach_cgroup\",\"errno\":%d}\n", errno); return 1; }
        int mfd = bpf_object__find_map_fd_by_name(obj, "net_events");
        struct ring_buffer *rb = ring_buffer__new(mfd, on_net_json, NULL, NULL);
        if (!rb) { printf("{\"error\":\"ringbuf\"}\n"); return 1; }
        printf("{\"ready\":true}\n");
        fflush(stdout);
        int limit = argc >= 5 ? atoi(argv[4]) : 0;
        while ((limit == 0 || got < limit)) {
            int rc = ring_buffer__poll(rb, 200);
            if (rc < 0 && rc != -EINTR && rc != -EAGAIN) break;
        }
        ring_buffer__free(rb);
        bpf_link__destroy(link);
    } else if (strcmp(mode, "net") == 0) {
        const char *cgpath = argc >= 4 ? argv[3] : "/sys/fs/cgroup/spike";
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "cg_egress");
        if (!prog) { printf("{\"error\":\"prog_not_found\"}\n"); return 1; }
        int cgfd = open(cgpath, O_RDONLY | O_DIRECTORY);
        if (cgfd < 0) { printf("{\"mode\":\"net\",\"error\":\"cgroup_open\",\"errno\":%d}\n", errno); return 1; }
        struct bpf_link *link = bpf_program__attach_cgroup(prog, cgfd);
        if (!link) {
            printf("{\"mode\":\"net\",\"error\":\"attach_cgroup\",\"errno\":%d,\"load_ms\":%.2f}\n", errno, load_ms);
            return 1;
        }
        printf("{\"mode\":\"net\",\"attach\":\"ok\",\"load_ms\":%.2f}\n", load_ms);
        fflush(stdout);
        /* keep attached while parent script probes connectivity */
        sleep(n > 0 ? n : 5);
        int sfd = bpf_object__find_map_fd_by_name(obj, "net_stats");
        unsigned int k0 = 0, k1 = 1;
        unsigned long long dropped = 0, passed = 0;
        bpf_map_lookup_elem(sfd, &k0, &dropped);
        bpf_map_lookup_elem(sfd, &k1, &passed);
        printf("{\"mode\":\"net\",\"stats_dropped\":%llu,\"stats_passed\":%llu}\n", dropped, passed);
        bpf_link__destroy(link);
    }
    bpf_object__close(obj);
    return 0;
}









