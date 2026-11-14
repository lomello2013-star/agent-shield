# Linux auditd → STML

The auditd collector is the no-eBPF path: it reads the kernel audit log, groups
one audit message (SYSCALL + EXECVE + PATH + PROCTITLE), normalizes it to Event
v3 and writes report JSONL for the STML connector.

## 1. Audit rules

Install a minimal rule set (adjust paths):

```bash
sudo tee /etc/audit/rules.d/90-aidf.rules >/dev/null <<'EOF'
# process execution
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S execveat -k exec
# network connect
-a always,exit -F arch=b64 -S connect -k connect
# file opens / deletes
-a always,exit -F arch=b64 -S openat -F success=1 -k open
-a always,exit -F arch=b64 -S unlink -k delete
-a always,exit -F arch=b64 -S unlinkat -k delete
# persistence-sensitive files
-w /etc/passwd -p wa -k persistence
-w /etc/shadow -p wa -k persistence
-w /etc/sudoers -p wa -k persistence
-w /etc/systemd/system -p wa -k persistence
EOF
sudo augenrules --load
sudo systemctl restart auditd
sudo auditctl -l | head
```

If auditd is not installed:

```bash
sudo apt update && sudo apt install -y auditd audispd-plugins
```

## 2. Install

```bash
sudo bash scripts/install_linux_audit_agent.sh
```

This copies `core/`, `schemas/`, `rules/`, `scripts/aidf_agent.py` into
`/opt/aidf`, installs `/etc/aidf/agent.toml` and the `aidf-auditd` unit.

Edit `/etc/aidf/agent.toml`:

```toml
[agent]
source = "linux.auditd"
audit_log = "/var/log/audit/audit.log"
data_root = "/var/lib/aidf"
report_events = true
```

Start:

```bash
sudo systemctl start aidf-auditd
sudo systemctl status aidf-auditd --no-pager
sudo journalctl -u aidf-auditd -n 30 --no-pager
```

Local panel (only on the host): `http://127.0.0.1:18080/ui/`. It shows live
health, collectors, recent verdicts and pending confirmations. Set `gui_port = 0`
to disable it.

One-shot test:

```bash
sudo python3 /opt/aidf/aidf_agent.py --config /etc/aidf/agent.toml --once
```

## 3. Verify

```bash
sudo ls -l /var/lib/aidf/reports/events.jsonl
sudo tail -n 2 /var/lib/aidf/reports/events.jsonl | python3 -m json.tool
```

The connector reads `data_root/reports/events.jsonl` (already in
`Connector._paths`) and sends `kind=event` reports to STML. A Linux agent then
appears in Fleet/Reports.

Generate a real event:

```bash
/bin/true
curl -s https://example.com >/dev/null || true
```

## 4. Rotation / reliability

- `LinuxAuditSource` tracks inode and offset; truncation/rotation starts at 0.
- A partial last line is kept until the newline arrives.
- Unsupported audit records are skipped; malformed groups do not stop the agent.
- Reporting failures never block detection; the connector retries from its spool.

## 5. Troubleshooting

| Symptom | Check |
|---|---|
| `source=linux.auditd` but no events | `auditctl -l`, `ausearch -ts recent` |
| `audit_log` unreadable | agent runs as root; check SELinux/AppArmor |
| events in report but not STML | connector `data_root` must match agent `data_root`; `stml-connector` task |
| no `reports/events.jsonl` | `report_events=false` in config |
| permission denied on audit log | `sudo -u root` / systemd `User=root` |

## 6. Limits

- auditd rules are host-wide; the agent does not change them automatically.
- A missing audit `key` is tolerated for well-known syscalls, but custom audit
  rules should set `-k`.
- This is a detector path, not a prevention driver: response actions are still
  gated by policy/confirmation.
