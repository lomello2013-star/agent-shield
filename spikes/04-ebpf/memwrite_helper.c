#define _GNU_SOURCE
// Test helper: child maps a buffer, reports its address via pipe; parent writes into
// that memory with process_vm_writev N times. Generates real cross-process writes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/uio.h>
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
        if (buf == MAP_FAILED) { perror("mmap"); _exit(1); }
        void *addr = buf;
        if (write(fds[1], &addr, sizeof(addr)) != sizeof(addr)) _exit(1);
        close(fds[1]);
        for (int i = 0; i < n * 10; i++) usleep(5000);   // stay alive
        _exit(0);
    }

    close(fds[1]);
    void *remote = NULL;
    if (read(fds[0], &remote, sizeof(remote)) != sizeof(remote)) { perror("read"); return 1; }
    close(fds[0]);

    char local[64];
    strcpy(local, "injected");
    int written = 0;
    for (int i = 0; i < n; i++) {
        struct iovec li = { .iov_base = local, .iov_len = sizeof(local) };
        struct iovec ri = { .iov_base = remote, .iov_len = sizeof(local) };
        ssize_t rc = process_vm_writev(child, &li, 1, &ri, 1, 0);
        if (rc > 0) written++;
    }
    printf("{\"writes\":%d,\"child\":%d}\n", written, (int)child);
    waitpid(child, NULL, 0);
    return written > 0 ? 0 : 2;
}

