# Product status and verification gates

## Built and committed

- Linux auditd agent + connector reports.
- Linux eBPF LSM guard (`aidf_enforce.bpf.o`, `aidf-enforce`, policy, unit, deb).
- Linux packages: deb + tar + rpm spec, eBPF objects/loader included.
- Windows:
  - `aidf-agent.exe` panel,
  - `aidf-service.exe` service,
  - Sysmon install/config,
  - Defender ASR/CFA/network hardening (auditв†’enforce),
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
- PowerShell scripts parse; Defender/service hardening dry-run plans verified.
- Helm lint/template (earlier).
- Local panel/STML smoke test (earlier).

## Not yet verified вЂ” blocks a "ready" claim

| Gate | Why | How to verify |
|---|---|---|
| eBPF LSM attach | **Verified in WSL**: `bpf` in `/sys/kernel/security/lsm`; loader attaches | Still validate on target Ubuntu kernel |
| eBPF deny exec | **Verified in WSL**: `Permission denied` + `denied:true` event | Validate on target VM |
| `apt update` under guard | **Verified in WSL** and **AIDF-Linux VM**: `APT_RC=0` | none |
| Windows service EXE | **Onedir build verified in AIDF-Win11 VM**: installed at `C:\Program Files\AIDefender\service`, service Running; no temp extraction | Reboot timing check |
| Sysmon channel | **Verified in AIDF-Win11 VM**: Sysmon64 Running; `win.sysmon` reports are produced | none |
| Defender ASR/CFA | **Verified in AIDF-Win11 VM**: audit (2/2/2) then enforce (1/1/1), ASR=9 | none |
| WDAC audit/enforce | **Verified in AIDF-Win11 VM**: enforce + SHA256 hash allowlist for the onedir tree; `AIDefender` and `Sysmon64` Running after reboot. Filepath-only rules fail for DLLs. | keep hashes updated per build |
| Windows response | **Verified in AIDF-Win11 VM**: firewall block/unblock, quarantine/restore, suspend/resume | none |
| STML end-to-end with guard | No live Linux guard events in STML | Linux VM в†’ connector в†’ STML |

## Next actions (ordered)

1. Create Ubuntu 24.04 VM with BPF LSM (`lsm=lockdown,capability,landlock,yama,apparmor,bpf`) and a second disk for tests.
2. Run eBPF guard audit/enforce; capture errors.
4. Install Windows service in a Windows 11 VM; install Sysmon; Defender auditв†’enforce.
5. Test response on benign process/file/firewall rule.
6. Send Linux guard events to STML; verify Reports.
7. Rebuild packages and produce release artifacts.

## Honest status

This is a **pilot build**, not a certified product. The Windows path is a user-mode
EDR-lite over Defender/Sysmon; the Linux path is kernel enforcement but must be
validated on a real kernel before calling it ready.


















| AppLocker | AuditOnly policy applied in AIDF-Win11 VM; enforce not enabled (no default allow rules) |




## Final lab verification (2026-11-15)

- AIDF-Linux-ISO: static 172.23.213.50; BPF LSM enabled via lsm=...,bpf; eBPF exec denied (/tmp/t2 RC=126) and persisted after reboot; pt-get update APT_RC=0.
- AIDF-Win11: AppLocker EXE Enforce with allow rules for %PROGRAMFILES%, %WINDIR%, AIDefender; WDAC AIDefender Enforce HashAllow IsEnforced=True; AIDefender and Sysmon64 Running; win.sysmon reports present.
- fanotify removed.

