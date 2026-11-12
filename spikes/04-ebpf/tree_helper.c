// Test helper: parent writes into the child's memory, the CHILD adds PROT_EXEC.
// This is the case pid-based correlation misses.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    int writes = argc > 1 ? atoi(argv[1]) : 5;
    int execs = argc > 2 ? atoi(argv[2]) : 5;
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
        usleep(300000);                       /* let the parent write first */
        int done = 0;
        for (int i = 0; i < execs; i++) {
            void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (page == MAP_FAILED) break;
            memcpy(page, "\x90\x90\xc3", 3);
            if (mprotect(page, 4096, PROT_READ | PROT_EXEC) == 0) done++;
            usleep(50000);
        }
        printf("{\"execs\":%d,\"child\":%d}\n", done, (int)getpid());
        fflush(stdout);
        usleep(300000);
        _exit(0);
    }

    close(fds[1]);
    void *remote = NULL;
    if (read(fds[0], &remote, sizeof(remote)) != sizeof(remote)) { perror("read"); return 1; }
    close(fds[0]);

    char local[64] = "injected";
    int done = 0;
    for (int i = 0; i < writes; i++) {
        struct iovec li = { .iov_base = local, .iov_len = sizeof(local) };
        struct iovec ri = { .iov_base = remote, .iov_len = sizeof(local) };
        if (process_vm_writev(child, &li, 1, &ri, 1, 0) > 0) done++;
        usleep(50000);
    }
    printf("{\"writes\":%d,\"parent\":%d}\n", done, (int)getpid());
    fflush(stdout);
    waitpid(child, NULL, 0);
    return 0;
}
