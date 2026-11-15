# Linux kernel-level prevention (fanotify)

`aidf_linux_guard.py` uses fanotify permission events to deny:

- execution from writable directories (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`);
- writable opens of protected system files, except allowlisted package managers.

It is kernel enforcement **without a kernel module** and without Microsoft
signing. It is not a kernel rootkit and does not protect against a root attacker
who stops the daemon.

## Requirements

- Linux with `CONFIG_FANOTIFY` and `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`;
- root / `CAP_SYS_ADMIN`;
- a filesystem that supports fanotify marks (ext4/xfs/btrfs; some overlay/network
  filesystems may not deliver permission events).

## Install

```bash
sudo bash scripts/install_linux_guard.sh
sudo nano /etc/aidf/guard.toml       # mode = "audit" first
sudo systemctl start aidf-guard
sudo journalctl -u aidf-guard -f
```

Expected start line:

```json
{"kind":"guard_ready","mode":"audit","mark":"/"}
```

## Audit → enforce

1. Run in `mode = "audit"`.
2. Trigger a benign test:
   ```bash
   cp /bin/true /tmp/aidf-guard-test && chmod +x /tmp/aidf-guard-test
   /tmp/aidf-guard-test
   ```
3. Check events in `/var/lib/aidf/guard/events.jsonl`.
4. Change to `mode = "enforce"`, restart, repeat: the exec should be denied.
5. Validate package manager updates still work (`apt update`).

## Configuration

```toml
[guard]
mode = "audit"      # audit | enforce
mark_path = "/"
deny_exec = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"]
protect_write = ["/etc/shadow", "/etc/sudoers", "/boot/", "/var/lib/aidf/"]
allow_write_processes = ["apt", "dpkg", "rpm", "systemctl"]
```

## STML

The guard writes `guard/events.jsonl` under the agent data root; the connector
tails it and sends `kind=guard` reports to STML.

## Limitations / validation

- WSL2 does not reliably expose fanotify permission events; validate on a
  real Linux host/VM.
- Marking `/` with `FAN_OPEN_PERM` can be expensive. Start with audit mode and
  measure.
- A root attacker can stop the daemon; use systemd hardening, ACLs and a
  separate management channel.
- This is a **pilot** component, not a certified AV/EDR.
