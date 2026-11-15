# Security review вЂ” pilot

Scope: AIDefender/STML pilot, excluding legal/EV/WHQL/HDC.

## Verified controls

- Windows service runs as LocalSystem; onedir under `C:\Program Files\AIDefender`.
- `C:\ProgramData\AIDefender` ACL: SYSTEM/Administrators full, Users read.
- WDAC hash-allowlist restricts unsigned code; AppLocker Exe/Dll/Script enforce.
- Defender ASR/CFA/NP in enforce mode.
- Firewall response rules are named `AIDF-block-*` and removable.
- Quarantine is encrypted with a per-install 32-byte key.
- Linux agent writes report JSONL only; eBPF guard is root-only.
- STML connector uses per-agent keys and an enrolment token.
- Linux logrotate 14 days; Windows maintenance task 30 days.

## Open risks

1. **No TLS for STML** вЂ” local HTTP on loopback/lab network. Do not expose remotely.
2. **Tokens** вЂ” stored in `tokens.json`/auth files; verify 0600 on Linux and ACL on Windows.
3. **Policy/update signing** вЂ” dev key only; production key rotation not implemented.
4. **Agent IPC** вЂ” local auth key; no OS-level peer verification beyond ACL.
5. **Windows service** вЂ” LocalSystem has broad rights; no PPL/ELAM (out of scope).
6. **WDAC hashes** вЂ” must be regenerated after every service build.
7. **PII** вЂ” command lines are hashed/redacted, paths not always.
8. **Update channel** вЂ” no signed A/B service update verified end-to-end.

## Required before wider use

- TLS or SSH tunnel for any non-loopback STML.
- File-permission audit for every token/key path.
- Replace dev signing keys; document rotation.
- Restrict STML bind address to loopback by default.
- Run the acceptance matrix on clean VMs.



