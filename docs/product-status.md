# Product status and verification gates

## Built and committed

- Linux auditd agent + connector reports.
- Linux fanotify guard (audit/enforce) + systemd + deb.
- Linux eBPF LSM guard (`aidf_enforce.bpf.o`, `aidf-enforce`, policy, unit, deb).
- Linux packages: deb + tar + rpm spec, eBPF objects/loader included.
- Windows:
  - `aidf-agent.exe` panel,
  - `aidf-service.exe` service,
  - Sysmon install/config,
  - Defender ASR/CFA/network hardening (audit→enforce),
  - WDAC audit policy generator,
  - Windows Firewall `block_network` response,
  - service recovery/ACL script,
  - EXE + MSI.
- STML:
  - Windows/Linux reports,
  - guard events path,
  - safe policy template with Sysmon,
  - signed A/B updates.

## Verified automatically

- Full `pytest`: 100% pass.
- Linux `.deb` builds and contains guard/eBPF/policy/units.
- Windows EXE/MSI/service EXE build.
- PowerShell scripts parse.
- Helm lint/template (earlier).
- Local panel/STML smoke test (earlier).

## Not yet verified — blocks a "ready" claim

| Gate | Why | How to verify |
|---|---|---|
| eBPF LSM attach | WSL has no `lsm=bpf` / securityfs | Ubuntu VM with `CONFIG_BPF_LSM`, `lsm=...,bpf` |
| eBPF deny exec | Needs real kernel | `/tmp/test` in enforce must fail |
| fanotify permission events | WSL does not deliver them reliably | Real Linux VM: audit event, then enforce deny |
| `apt update` under guard | Must not break package manager | audit/enforce + apt |
| Windows service EXE | Current service is Python; not replaced | Lab VM: install_service, reboot, health |
| Sysmon channel | Sysmon not installed on this host | Install signed Sysmon, restart service |
| Defender ASR/CFA | Not applied (would change host) | VM: audit, review, enforce |
| WDAC audit | Not deployed | VM: CiTool, CodeIntegrity log |
| Windows response | Not tested on benign process/file | VM: suspend/quarantine/firewall |
| STML end-to-end with guard | No live Linux guard events in STML | Linux VM → connector → STML |

## Next actions (ordered)

1. Create Ubuntu 24.04 VM with BPF LSM (`lsm=lockdown,capability,landlock,yama,apparmor,bpf`) and a second disk for tests.
2. Run eBPF guard audit/enforce; capture errors.
3. Run fanotify fallback; compare.
4. Install Windows service in a Windows 11 VM; install Sysmon; Defender audit→enforce.
5. Test response on benign process/file/firewall rule.
6. Send Linux guard events to STML; verify Reports.
7. Rebuild packages and produce release artifacts.

## Honest status

This is a **pilot build**, not a certified product. The Windows path is a user-mode
EDR-lite over Defender/Sysmon; the Linux path is kernel enforcement but must be
validated on a real kernel before calling it ready.
