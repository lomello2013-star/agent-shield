# Linux eBPF LSM prevention

Primary Linux kernel-enforcement path. The fanotify guard remains a fallback for
kernels/filesystems where eBPF LSM is unavailable.

## Requirements

- kernel with `CONFIG_BPF_LSM=y`;
- `lsm=...,bpf` on the kernel command line;
- root/CAP_BPF/CAP_SYS_ADMIN;
- libbpf at build time.

Check:

```bash
cat /sys/kernel/security/lsm      # must contain bpf
```

## Build

```bash
sudo bash scripts/build_linux_ebpf.sh dist/ebpf
python3 scripts/linux_object_manifest.py --src dist/ebpf
python3 scripts/sign_linux_manifest.py   # dev key only
```

## Run

```bash
sudo /opt/aidf/aidf-enforce audit /opt/aidf/aidf_enforce.bpf.o /etc/aidf/enforce.policy
```

Policy format:

```text
exec=/tmp/
write=/etc/shadow
```

The loader hashes every path prefix at `/`, so `exec=/tmp/` covers
`/tmp/anything`.

- `audit` — emits events, allows everything.
- `enforce` — returns `-EACCES` for matching exec/write.

## systemd

`aidf-ebpf-guard.service` starts in **audit** mode. Change `ExecStart` to
`enforce` only after validating on the target kernel/VM.

## Validation (must be on real Linux)

1. Boot a VM with `lsm=...,bpf`.
2. Confirm `bpf` in `/sys/kernel/security/lsm`.
3. Run audit; execute `/tmp/test`; see `kind=exec`.
4. Run enforce; execute `/tmp/test`; expect `Permission denied`.
5. Check `apt update` still works; protected writes use allowlisted processes
   via the fanotify fallback or package-manager policy.

WSL2 usually lacks BPF LSM; do not treat WSL as validation.

### Result on this WSL kernel (2026-11)

- `/sys/kernel/security/lsm` contains `bpf`;
- loader attaches `aidf_exec` and `aidf_open`;
- audit mode: `/tmp/aidf_ebpf_test` runs, event `denied:false`;
- enforce mode: same exec returns `Permission denied`, event `denied:true`.
- protected-write exact-path enforcement is **not yet verified**; exec enforcement is.

Still validate on the target Ubuntu/RHEL kernel before calling it ready.

## Limits

- no network/memory hooks in this program; use the existing eBPF telemetry
  streams and auditd;
- a root attacker can stop the daemon;
- this is a pilot, not a certified AV/EDR.
