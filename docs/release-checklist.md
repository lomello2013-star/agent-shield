# AIDefender/STML pilot release checklist

Status: **pilot / lab-only**. Not production-certified. No EV/WHQL/HDC or legal entity.

## Linux — verified

- [x] Ubuntu 24.04 VM, static IP `172.23.213.50/20`.
- [x] SSH key login.
- [x] BPF LSM enabled: `lsm=lockdown,capability,landlock,yama,apparmor,bpf`.
- [x] `aidf-ebpf-guard.service` active at boot.
- [x] eBPF exec deny: `/tmp/t2` → `Permission denied` (RC 126), survives reboot.
- [x] `apt-get update` under enforce: `APT_RC=0`.
- [x] `.deb` and `.rpm` built and installed.
- [x] Signed object manifest (`objects.sha256` + `.sig`).
- [ ] eBPF write-deny re-tested on this final VM.
- [ ] fanotify removed; fallback is auditd only.

## Windows — verified

- [x] Onedir service at `C:\Program Files\AIDefender\service`.
- [x] `AIDefender` service Running after reboot.
- [x] Sysmon64 Running; `win.sysmon` events produced.
- [x] Defender ASR/CFA/NP audit → enforce.
- [x] WDAC enforce with SHA256 hash allowlist (`AIDefender Enforce HashAllow`, IsEnforced=True).
- [x] AppLocker enforce for **Exe + Dll + Script**; allow rules for `%WINDIR%`, `%PROGRAMFILES%`, `C:\Program Files\AIDefender`.
- [x] Firewall block/unblock, quarantine/restore, suspend/resume tested on benign objects.
- [x] Service recovery + ACL hardening applied.
- [ ] Re-run WDAC after any binary change (hashes must be regenerated).

## STML

- [x] guard event → connector → STML report (`kind=guard`) in WSL.
- [x] Unit tests: full `pytest` pass.
- [ ] Live end-to-end test on the final Linux VM.

## Release gates

- [ ] Rebuild packages from final commit.
- [ ] Regenerate `objects.sha256` + signature.
- [ ] Regenerate WDAC hash-allowlist after service rebuild.
- [ ] Acceptance run on clean Linux + Windows VMs.
- [ ] No production claim; attach this checklist to the pilot release.

## Known limitations

- AppLocker DLL enforcement can affect performance; validate on target.
- WDAC hashes are build-specific.
- No kernel driver on Windows; no PPL/ELAM.
- EV/WHQL/HDC and legal certification are frozen/out of scope.
