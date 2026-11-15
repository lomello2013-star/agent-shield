# Чек-лист пилотного релиза AIDefender/STML

Статус: **pilot / lab-only**. Не production. EV/WHQL/HDC и юрчасть заморожены.

## Linux — проверено

- [x] Ubuntu 24.04 VM, статический IP `172.23.213.50/20`.
- [x] Вход по SSH-ключу.
- [x] BPF LSM включён: `lsm=lockdown,capability,landlock,yama,apparmor,bpf`.
- [x] `aidf-ebpf-guard.service` активен при загрузке.
- [x] eBPF exec deny: `/tmp/t2` → `Permission denied` (RC 126), переживает reboot.
- [x] `apt-get update` под enforce: `APT_RC=0`.
- [x] `.deb` и `.rpm` собраны и установлены.
- [x] Подписанный манифест объектов (`objects.sha256` + `.sig`).
- [ ] eBPF write-deny перепроверить на финальной VM.
- [ ] fanotify удалён; fallback — только auditd.

## Windows — проверено

- [x] Onedir-служба в `C:\Program Files\AIDefender\service`.
- [x] Служба `AIDefender` Running после reboot.
- [x] Sysmon64 Running; события `win.sysmon` пишутся.
- [x] Defender ASR/CFA/NP: audit → enforce.
- [x] WDAC enforce с SHA256 hash-allowlist (`AIDefender Enforce HashAllow`, IsEnforced=True).
- [x] AppLocker enforce для **Exe + Dll + Script**; allow-правила:
  - `%WINDIR%\*`
  - `%PROGRAMFILES%\*`
  - `C:\Program Files\AIDefender\*`
- [x] Firewall block/unblock, quarantine/restore, suspend/resume проверены на benign-объектах.
- [x] Service recovery + ACL hardening применены.
- [ ] После любого изменения бинарников пересобрать WDAC hash-allowlist.

## STML

- [x] guard event → connector → STML report (`kind=guard`) в WSL.
- [x] Полный `pytest` — pass.
- [ ] Live end-to-end на финальной Linux VM.

## Гейты релиза

- [ ] Пересобрать пакеты с финального коммита.
- [ ] Пересчитать `objects.sha256` + подпись.
- [ ] Пересчитать WDAC hash-allowlist после пересборки сервиса.
- [ ] Приёмочный прогон на чистых Linux + Windows VM.
- [ ] Не заявлять production; приложить этот чек-лист к пилоту.

## Известные ограничения

- AppLocker DLL enforcement может влиять на производительность; проверять на целевом ПК.
- WDAC-хеши привязаны к конкретной сборке.
- На Windows нет собственного драйвера; нет PPL/ELAM.
- EV/WHQL/HDC и юридическая сертификация — вне scope.
