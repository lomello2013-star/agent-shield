# Acceptance report — AIDefender/STML pilot

Дата: 2026-11-15. Статус: **pilot / lab**, не production.
EV/WHQL/HDC и юридическая сертификация — вне scope.

## Linux

VM: `AIDF-Linux-ISO`, Ubuntu 24.04, kernel 6.8, static `172.23.213.50/20`.

| Проверка | Результат |
|---|---|
| BPF LSM | `lsm=...bpf` |
| eBPF exec deny | `/tmp/t2` → Permission denied, RC 126 |
| eBPF write deny | `write=/tmp/wtest` → denied |
| reboot persistence | unit active после reboot |
| apt under enforce | `APT_RC=0` |
| auditd fallback | active без eBPF |
| pydantic v2 package | 2.14.3 в `/opt/aidf/venv` |
| logrotate | 14 дней, reports/audit/raw |

## Windows

VM: `AIDF-Win11`, Windows 11.

| Проверка | Результат |
|---|---|
| service | onedir, Running после reboot |
| Sysmon | Running, `win.sysmon` events |
| Defender | audit → enforce (ASR/CFA/NP) |
| WDAC | Enforce HashAllow, IsEnforced=True |
| AppLocker | Exe/Dll/Script Enabled |
| response | firewall, quarantine/restore, suspend/resume |
| uninstall/rollback | service/AppLocker/WDAC/firewall сняты; Defender AuditMode |
| reinstall/upgrade | Running после reboot |
| watchdog | остановленная служба поднята |

## STML

| Проверка | Результат |
|---|---|
| live Linux → STML | 1 guard report |
| live Windows → STML | 50 reports |
| HTTPS | self-signed health OK |
| mTLS | без cert reject, с cert OK |
| non-loopback guard | требует `--allow-remote` |
| русский UI | STML + agent panel визуально |
| approvals → quarantine | тест прошёл |

## Сборка

| Проверка | Результат |
|---|---|
| deb reproducible | byte-identical |
| rpm reproducible | byte-identical |
| release manifest | `dist/release-manifest.json` |
| CI workflow | YAML валиден, GitHub run не выполнялся |

## Clean Ubuntu acceptance

Fresh Ubuntu 24.04 cloud VM (`AIDF-Ubuntu-Accept2`, 172.23.213.60), converted
from the bootable qcow2 image (not the rootfs image).

| Step | Result |
|---|---|
| install `python3-venv`, `auditd`, `.deb` | package installed |
| service after install | `aidf-auditd: active`, `auditd: active` |
| reboot | service active again |
| reinstall same `.deb` | active |
| remove package | `REMOVE_RC=0`, service inactive, package `rc` |
| reinstall | active |

The first package build had a broken `postrm` (it contained `postinst`
contents); fixed by removing venv creation from `postrm` and rebuilding.

## Windows clean VM

Not performed: the Windows 11 install ISO is not present in `D:\vm` (only
`answer.vhdx`/`unattend.iso` and the existing installed disk). A real
clean install needs the ISO or a clean VM image.

## Not closed

- RPM live на Fedora/RHEL — нет Fedora VM.
- CI на GitHub — нет remote/credentials.
- Clean-VM acceptance на чистом Windows/Ubuntu с нуля — частично.
- Full pytest одним процессом после длинной сессии — Windows socket exhaustion.

## Вывод

Продукт пригоден для **pilot/lab** на подготовленных VM.  
Для production нужны: clean-VM acceptance, Fedora/RHEL, CI run и юридическая сертификация (заморожена).
