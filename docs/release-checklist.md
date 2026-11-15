# Чек-лист пилотного релиза AIDefender/STML

Статус: **pilot / lab-only**. Не production. EV/WHQL/HDC и юрчасть заморожены.

## Linux — проверено

- [x] Ubuntu 24.04 VM, статический IP `172.23.213.50/20`.
- [x] Вход по SSH-ключу.
- [x] BPF LSM: `lsm=lockdown,capability,landlock,yama,apparmor,bpf`.
- [x] `aidf-ebpf-guard.service` активен после reboot.
- [x] eBPF exec deny: `/tmp/t2` → `Permission denied` (RC 126).
- [x] eBPF write deny: `write=/tmp/wtest`.
- [x] `apt-get update` под enforce: `APT_RC=0`.
- [x] `.deb` и `.rpm` собраны.
- [x] Pydantic 2.14.3 в `/opt/aidf/venv`.
- [x] auditd fallback активен без eBPF.
- [x] logrotate reports/audit/raw — 14 дней.

## Windows — проверено

- [x] Onedir-служба в `C:\Program Files\AIDefender\service`.
- [x] `AIDefender` Running после reboot.
- [x] `Sysmon64` Running, события `win.sysmon`.
- [x] Defender ASR/CFA/NP audit → enforce.
- [x] WDAC enforce + SHA256 hash-allowlist.
- [x] AppLocker Exe + Dll + Script enforce.
- [x] Firewall block/unblock.
- [x] Quarantine/restore.
- [x] Suspend/resume.
- [x] Uninstall/rollback и reinstall/upgrade.
- [x] Watchdog: остановленная служба поднимается.
- [x] Log maintenance 30 дней.

## STML

- [x] Live Linux → connector → STML (1 guard report).
- [x] Live Windows → connector → STML (50 reports).
- [x] HTTPS self-signed.
- [x] mTLS: без cert reject, с cert OK.
- [x] non-loopback bind требует `--allow-remote`.
- [x] Русский STML UI и динамические статусы.
- [x] Русский agent panel в пересобранном EXE/MSI.

## Гейты релиза

- [x] Пакеты пересобраны.
- [x] `objects.sha256` + подпись.
- [x] Release manifest / SBOM.
- [x] CI workflow добавлен.
- [ ] CI реально прогнан на GitHub.
- [ ] Clean-VM acceptance на чистом Ubuntu/Windows.
- [ ] RPM live на Fedora/RHEL.

## Известные ограничения

- AppLocker DLL enforcement может влиять на производительность.
- WDAC hashes нужно пересчитывать после каждой сборки сервиса.
- Нет собственного Windows-драйвера/PPL/ELAM.
- EV/WHQL/HDC и юридическая сертификация — вне scope.
