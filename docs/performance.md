# Performance smoke — Linux eBPF

Host: `AIDF-Linux-ISO` (Ubuntu 24.04, 2 vCPU, kernel 6.8, BPF LSM).
Test: 300 sequential `/bin/true` executions.

Results:

| State | real | user | sys |
|---|---:|---:|---:|
| eBPF enforce active | 0.359 s | 0.117 s | 0.220 s |
| eBPF stopped | 0.302 s | 0.120 s | 0.197 s |

Approximate overhead: **~0.19 ms per exec**, ~19% on this microbenchmark.
Guard process RSS: **2.7 MB**.

This is a lab microbenchmark, not a full workload test. Validate on the target
kernel and real application mix before sizing.

Notes:

- eBPF exec deny uses static prefixes; no per-file map scan on exec.
- Write denial uses inode map; test `/etc` write path separately.
- AppLocker DLL enforcement on Windows adds its own overhead; measure separately.
