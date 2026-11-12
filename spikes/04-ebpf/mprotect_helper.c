// Test helper: map anonymous RW pages, then mprotect each to RX (adds PROT_EXEC).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
    int n = argc > 1 ? atoi(argv[1]) : 20;
    int done = 0;
    for (int i = 0; i < n; i++) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) break;
        memcpy(p, "\x90\x90\x90\xc3", 4);            /* nop; nop; nop; ret */
        if (mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0)
            done++;
    }
    printf("{\"mprotects\":%d}\n", done);
    return done > 0 ? 0 : 2;
}
