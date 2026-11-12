// Test helper: parent writes into a child's memory via /proc/<pid>/mem N times.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    int n = argc > 1 ? atoi(argv[1]) : 20;
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); return 1; }

    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        char *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) _exit(1);
        void *addr = buf;
        if (write(fds[1], &addr, sizeof(addr)) != sizeof(addr)) _exit(1);
        close(fds[1]);
        for (int i = 0; i < n * 10; i++) usleep(5000);
        _exit(0);
    }

    close(fds[1]);
    void *remote = NULL;
    if (read(fds[0], &remote, sizeof(remote)) != sizeof(remote)) { perror("read"); return 1; }
    close(fds[0]);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)child);
    char payload[8] = "INJECT!";
    int written = 0;
    for (int i = 0; i < n; i++) {
        int fd = open(path, O_RDWR);          /* one open per write: LSM fires per open */
        if (fd < 0) break;
        ssize_t rc = pwrite(fd, payload, sizeof(payload), (off_t)remote);
        if (rc > 0) written++;
        close(fd);
    }
    printf("{\"writes\":%d,\"child\":%d}\n", written, (int)child);
    waitpid(child, NULL, 0);
    return written > 0 ? 0 : 2;
}

