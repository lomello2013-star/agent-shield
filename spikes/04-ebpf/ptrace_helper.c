// Test helper: parent PTRACE_ATTACH + PTRACE_POKEDATA into a child's mapped buffer.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
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

    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) != 0) { perror("ptrace attach"); return 1; }
    waitpid(child, NULL, 0);

    int written = 0;
    for (int i = 0; i < n; i++) {
        if (ptrace(PTRACE_POKEDATA, child, remote, (void *)0x4141414142424242UL) == 0)
            written++;
    }
    ptrace(PTRACE_DETACH, child, NULL, NULL);
    printf("{\"pokes\":%d,\"child\":%d}\n", written, (int)child);
    waitpid(child, NULL, 0);
    return written > 0 ? 0 : 2;
}
