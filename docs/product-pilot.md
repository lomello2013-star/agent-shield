# AIDefender/STML pilot product

Scope: maximum protection that does not require Microsoft driver signing or a
legal entity. EV/WHCP/HDC are deliberately out of scope.

## Components

| Component | Where | Role |
|---|---|---|
| STML server | `127.0.0.1:8080` | fleet, policies, approvals, reports, audit |
| STML Rust server | `127.0.0.1:8090` | PostgreSQL/parity path |
| Windows service | `aidf-service.exe` | daemon, rules, audit, response |
| Windows panel | `aidf-agent.exe` / localhost | local health, decisions |
| Windows hardening | Sysmon + Defender ASR/CFA + Firewall | prevention/telemetry without our driver |
| Linux auditd agent | `aidf-agent.py` | auditd → STML |
| Linux guard | `aidf-linux-guard.py` | fanotify exec/write denial (pilot) |
| Linux eBPF guard | `aidf-enforce` + `.bpf.o` | kernel LSM exec/write denial (primary) |
| Updates | signed A/B bundles | versioned updates/rollback |

## Windows install order

```powershell
# 1. agent/panel package
powershell -File packaging\windows\build_windows_exe.ps1
powershell -File packaging\windows\build_windows_service.ps1
# elevated:
powershell -File packaging\windows\install_service.ps1
powershell -File packaging\windows\install_aidf_agent.ps1

# 2. Sysmon (download Sysmon64.exe from Sysinternals)
powershell -File packaging\windows\install_sysmon.ps1 -Sysmon C:\Tools\Sysmon64.exe

# 3. Defender hardening: audit first, then enforce
powershell -File packaging\windows\harden_defender.ps1
powershell -File packaging\windows\harden_defender.ps1 -Apply          # audit
# after review:
powershell -File packaging\windows\harden_defender.ps1 -Apply -Enforce

# 3b. optional WDAC audit policy
powershell -File packaging\windows\build_wdac_audit.ps1

# 4. optional service recovery/ACL
powershell -File packaging\windows\harden_service.ps1
powershell -File packaging\windows\harden_service.ps1 -Apply
```

## Linux install order

```bash
sudo bash scripts/install_linux_audit_agent.sh
sudo bash scripts/install_linux_guard.sh
sudo nano /etc/aidf/guard.toml     # audit first
sudo systemctl start aidf-guard
```

eBPF LSM primary (kernel must have `lsm=...,bpf`):

```bash
sudo bash scripts/build_linux_ebpf.sh dist/ebpf
sudo bash scripts/install_linux_ebpf_guard.sh
sudo systemctl start aidf-ebpf-guard   # audit mode in the unit
```

For package builds:

```bash
VERSION=0.1.0 bash packaging/build_linux_packages.sh --objects dist/ebpf
```

## What is actually prevention

| Layer | Mechanism | Pre-execution? |
|---|---|---|
| Windows | Defender ASR/CFA/WDAC | yes |
| Windows | Windows Firewall | network |
| Windows | user-mode response | after detection |
| Windows | Sysmon | telemetry only |
| Linux | fanotify guard | yes (exec/write) |
| Linux | auditd | telemetry |
| Linux | eBPF LSM | optional future |

## Hard limits

- No own Windows kernel driver (frozen).
- No WHQL/EV/HDC.
- No PPL/ELAM/ETW-TI.
- No guaranteed protection against kernel rootkits or a local admin.
- Linux guard must be validated on the target kernel; WSL is not enough.

## Acceptance

- [ ] Windows service starts at boot and survives restart.
- [ ] Sysmon channel present; `win.sysmon` source active.
- [ ] Defender ASR/CFA in Audit, then Enforce.
- [ ] STML shows Windows + Linux agents.
- [ ] Linux guard denies `/tmp` exec in a **real Linux VM**.
- [ ] `apt update` still works with guard enforce.
- [ ] Quarantine/suspend/block_network tested on benign objects.
- [ ] Update/rollback tested.
- [ ] No claim of production certification.
