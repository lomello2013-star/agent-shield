# AIDefender/STML v0.1.0 — pilot release

Status: **pilot / lab-only**. Not production-certified.
EV/WHQL/HDC and legal certification are out of scope and frozen.

## Artifacts

| File | Purpose |
|---|---|
| `aidf-auditd_0.1.0_amd64.deb` | Ubuntu/Debian agent, systemd, eBPF, auditd fallback |
| `aidf-auditd-0.1.0-1.x86_64.rpm` | Fedora/RHEL-compatible agent |
| `aidf-auditd-0.1.0.tar.gz` | Portable files |
| `aidf-ebpf-linux.zip` | eBPF objects, loader, policy, manifest |
| `aidf-windows-pilot.zip` | Windows agent, onedir service, Sysmon/Defender/WDAC/AppLocker scripts |
| `SHA256SUMS` | Artifact checksums |
| `objects.sha256` + `.sig` | Linux eBPF manifest/signature |

## Verified in lab

- Linux eBPF exec/write deny on Ubuntu 24.04, survives reboot.
- `apt-get update` under enforce.
- Fedora 43: RPM install, auditd + `aidf-auditd` active, `linux.auditd` events.
- Windows: onedir service, Sysmon, Defender enforce, WDAC hash-allowlist, AppLocker Exe/Dll/Script, firewall/quarantine/suspend, rollback/reinstall/upgrade, watchdog.
- STML live Linux + Windows, HTTPS/mTLS, Russian UI.
- Full `pytest` pass.
- Reproducible `.deb`/`.rpm`.
- GitHub CI success.

## Known limitations

- AppLocker DLL enforcement can affect performance.
- WDAC hashes are build-specific; regenerate after every service build.
- No own Windows kernel driver/PPL/ELAM.
- Clean-VM acceptance on fresh Ubuntu/Windows is not complete.
- Fanotify was removed as unstable.
- No production certification.

## Install

Linux:

```bash
sudo apt install ./aidf-auditd_0.1.0_amd64.deb
sudo systemctl status aidf-auditd
```

Windows:

```powershell
Expand-Archive aidf-windows-pilot.zip
# elevated:
install_product.ps1
```

See `release-checklist.md`, `acceptance-report.md`, `security-review.md`.
