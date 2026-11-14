# Red-team: первый измеряемый срез (Windows, безопасная эмуляция)

> Это **не** «20 сценариев/ОС» и не доказательство E1–E6. Это срез, который
> отделяет «правило совпало с фикстурой» от «продукт сработал на живом событии
> в VM». Реальные образцы вредоносного ПО не использовались.

## Как запустить

```powershell
$env:AIDF_VM_USER = "aidf"
$env:AIDF_VM_PASS = "<lab password>"
$env:AIDF_ADMIN_TOKEN = "<service admin token>"
$env:AIDF_AUTHKEY = "<hex auth key>"
powershell -ExecutionPolicy Bypass -File scripts\redteam_windows.ps1
```

Харнесс копирует `scripts/redteam_vm.ps1` в VM, запускает сценарии, забирает
`artifacts/redteam_windows.json`. VM должна быть запущена; служба `AIDefender` и
(опционально) Sysmon — работать.

## Сценарии

| ID | Техника | Действие | Ожидаемое правило |
|---|---|---|---|
| RT-WIN-01 | T1543.003 | `sc create AidfRtSvc` (7045) | `WIN-SERVICE-CREATE-007` |
| RT-WIN-02 | T1204 | запуск `C:\Temp\rt_tick.exe` | `WIN-EXEC-TEMP-001` |
| RT-WIN-03 | T1059.001 | `powershell -EncodedCommand` (sleep) | `WIN-PS-ENCODED-002` |
| RT-WIN-04 | control + E6 | benign `cmd /c exit`; запись в `C:\AIDefender\protected` | нет вердикта; драйвер блокирует |

Для RT-WIN-02/03 харнесс дожидается pending-подтверждения с `target = PID`,
одобряет его через `aidfctl confirm --params-file` и проверяет, что процесс
приостановлен (для RT-WIN-02 — по остановке роста `tick.bin`). RT-WIN-01
ожидаемо **не** предотвращается: у 7045 нет `actor_pid`, действие
пропускается (`action_skipped`).

## Результат (2026-11-14, AIDF-Win11)

| Метрика | Значение |
|---|---|
| Сценариев | 4 |
| Обнаружено | **3 / 3** атакующих (RT-WIN-04 — контроль, не атака) |
| Предотвращено | **3** (RT-WIN-02/03 — suspend; RT-WIN-04 — драйвер) |
| FP на benign-контроле | **0** |
| Драйвер | `AidfFilter` загружен, protected write → **Access denied** |
| Артефакт | `artifacts/redteam_windows.json` |

## Найденный дефект (исправлен)

Первый прогон дал **2/4**: RT-WIN-03 не сработал. Причина — правило
`WIN-PS-ENCODED-002` смотрит `platform_data.cmdline`, а нормализатор Sysmon
заполнял только `actor.cmdline_redacted`; `platform_data` не содержал `cmdline`.
Исправлено в `core/normalize.py` (добавлены `cmdline`, `image`, `parent_name`),
тест `test_win_eventlog_builds_actor_from_process_id` расширен. Повторный прогон
— **3/3**.

## Ограничения (честно)

- Одна VM, один прогон; нет 20 сценариев/ОС, нет реальных образцов, нет
  скрытого holdout.
- E3/E4 (credential access, privilege escalation) и Linux-live не покрыты;
  Linux-полигон измеряет fapolicyd отдельно (10/10), это не red-team агента.
- Драйвер — **test-signed lab**; production требует EV + WHQL, ELAM/ETW-TI и
  связи с user-mode политикой.
- «Обнаружено 3/3» — это три эмуляции, а не доказательство E1–E6; для целей
  §эффективности нужен полный red-team-план и benign-корпус для FPR.

## Следующий шаг

1. Расширить до 20 сценариев/ОС (по реестру `docs/hack-windows-register.md`).
2. Добавить benign-корпус (FPR) и скрытый holdout.
3. E3/E4: credential access и privilege escalation — на изолированной VM.
4. Связать драйвер с вердиктом агента (IOCTL/FltSendMessage) вместо
   фиксированного пути.

## 20 сценариев/ОС — первый срез (2026-11-14)

Каталог: **20 Windows + 20 Linux** по реестру техник; для Windows 15 безопасных
сценариев выполнены, 5 деструктивных (LSASS dump, injection, log clear,
vssadmin, local user) помечены catalog-only.

### Windows (live, `artifacts/redteam20_windows.json`)

| Метрика | Значение |
|---|---|
| Выполнено / пропущено | **15 / 5** |
| Атакующих сценариев | 11 |
| Обнаружено | **9 / 11** |
| Holdout (5) | **4 / 5** (WIN-04, WIN-06, WIN-08, WIN-16) |
| Benign-контроль | 4, **0 FP** |

**Обнаружены (9):** service create (007), temp exec (001), encoded PowerShell
(002), temp cmd (001), **scheduled task (006)**, **Run key (005)**,
**Defender exclusion (009)**, **WMI subscription (018)**, masquerade (011).
**Пропущены (честно):**
- Downloads exec (WIN-17) — правило 016 требует `integrity.verified=false`;
  `calc.exe` подписан, поэтому это корректный non-match, а не пропуск;
- service start (WIN-18) — 7036 не даёт нового 7045.

**Defender exclusion (WIN-08) закрыт:** 5007 писался, но
`classify_defender_change` не видел ключ `Exclusions\Paths` (был только
`exclusionpath`) → классифицировал как benign. Добавлены
`exclusions\paths|processes|extensions`; live `WIN-DEFENDER-TAMPER-009` = 7.

**FP 010 устранён:** источник — `powershell.exe → CreateRemoteThread` в
`<unknown process>` (PS Direct). Правило 010 теперь требует
`object.path = *.exe`; `<unknown process>` очищается в нормализаторе. Контроль
WIN-10 больше не даёт `INJECT-010`.

**Ambient 7045 больше не FP:** правило 007 сужено на `users/temp/tmp/
programdata`; кроме того, атрибуция идёт по `event_ts` из audit
(`Get-VerdictsSince`), поэтому запоздавшие события не приписываются контролю.
Общая детекция service install без suspicious-пути теперь **не** даёт high —
alert-правило для generic pending (D-001).

Это не «9/11 эффективности»: каталог показывает **source gaps**, а не только
качество правил; два пропуска объяснены (signed non-match и 7036). Для E1–E6
нужны реальные образцы и полный 20/ОС прогон.

### Linux

20-сценарный Linux-прогон **не выполнялся**, но появился **live exec-срез**:
в Linux-VM собран `exec_path` CO-RE, loader `stream` дал 3 live-события
(`cp`, `/tmp/aidf_exec_live`, `/bin/true`); product `linux.ebpf`-адаптер + правила
выдали ровно **`LINUX-EXEC-TMP-101`**, benign `/bin/true` — без вердикта
(`artifacts/linux_ebpf_live.json`).

**bpf LSM включён:** добавлен `lsm=...,bpf` в cloudimg `GRUB_CMDLINE_LINUX`
(`/etc/default/grub.d/99-ima.cfg`), reboot; active LSM содержит `bpf`. Live
cred-read: `cat /etc/shadow` → **`LINUX-CRED-READ-104`**, `sshd` исключён
allowlist (иначе легитимная аутентификация давала FP).

**Итого Linux live: 17 сценариев** — exec (`101`), cred-read (`104`),
mprotect (`107`), procmem/ptrace/memwrite (`106`), net C2 (`105`),
SMB lateral (`012`), cron (`102`), audit tamper (`103`), корреляция injection
(`108/109/110`), mass-write (`014`), canary delete (`015`), exfil-bytes (`017`),
DNS long (`013`); все прошли через `linux.ebpf`-адаптер и правила.
Остальные 3 из 20 — Windows-only (N/A для Linux, D-012), поэтому корректная
метрика — **17/17 applicable live**.

| Сценарий | События | Вердикт |
|---|---|---|
| exec `/tmp/...` | 3 (вкл. benign `/bin/true`) | `LINUX-EXEC-TMP-101` ×1 |
| cred read `/etc/shadow` | 2 (`cat`, `sshd`) | `LINUX-CRED-READ-104` ×1 (sshd исключён) |
| mprotect RW→RX anon | 5 | `LINUX-EXEC-MEM-107` ×5 |
| `/proc/<pid>/mem` write | 5 | `LINUX-INJECT-106` ×5 |
| ptrace POKEDATA | 5 | `LINUX-INJECT-106` ×5 |
| process_vm_writev | 5 | `LINUX-INJECT-106` ×5 |
| connect 4444 (root cgroup) | 3 (`4444`, `443`) | `LINUX-C2-PORT-105` ×1 |
| cron drop `touch /etc/cron.d` | 4 (`cron`, `audit`) | `LINUX-CRON-102` ×1 |
| audit log `touch /var/log/audit` | 4 | `LINUX-AUDIT-TAMPER-103` ×1 |
| corr_helper: memwrite + mprotect | 10 | `CORR-108/109/110` ×5 каждый |
| connect 445 + 4444 | 2 | `NET-SMB-LATERAL-012`, `LINUX-C2-PORT-105` |
| 50 × `touch /tmp/aidf_write_*` | 50 | `FILE-MASS-WRITE-014` ×1 |
| `rm /tmp/aidf_canary_test` | 2 | `FILE-CANARY-015` ×1 |
| sendto 12 MB UDP | 1 | `NET-EXFIL-LARGE-017` ×1 |
| DNS qname 50 символов | 2 (длинный + короткий) | `NET-DNS-LONG-013` ×1 |

**Net live:** attach к **root cgroup** `/sys/fs/cgroup` (процессы VM там, `/aidf`
пуст) дал события; `connect 4444` → `LINUX-C2-PORT-105`, `443` — без вердикта.

Прототип production-коллектора есть (`scripts/linux_ebpf_agent.py`, 10 потоков,
audit JSONL); systemd/подпись/очередь остаются open. fapolicyd
блокировал clang/loader (`EPERM`), на тест останавливался и возвращён.

### Найденный дефект харнесса

`Get-RuleDelta` был назван `Diff`; PowerShell-алиас `diff → Compare-Object`
перекрыл функцию, и первый прогон дал 0/11. Переименовано; повторный прогон —
5/11. Это дефект измерения, а не детекции.

### Закрытие source gaps (14.11)

| Gap | Что сделано | Статус |
|---|---|---|
| Security 4698 (schtasks) | `auditpol Other Object Access Events` + opt-in `win.security` (`AIDF_SECURITY=1`) | **live: 006 = 2 за 8 с; WIN-05 detected** |
| FileCreate 11 | Swift Sysmon config; события 11 пишутся | live |
| Registry 12/13/14 | Swift config + маппинг; `WIN-06` Run key detected | **live** |
| WMI 19/20/21 | WMI-subscription через `Set-WmiInstance`; `WIN-09` detected | **live (018)** |
| Ложный `stalled` | heartbeat на успешный poll (даже 0 записей) | fixed |

`win.sysmon` подписан на 1/8/10/11/12/13/14/19/20/21; `win.security` —
4698/4720/4688/1102. После закрытия 4698/registry/WMI/Defender-классификации и
audit-атрибуции 20-срез: **9/11**, holdout **4/5**, **0 FP**; FP 010 устранён;
оба пропуска объяснены (signed non-match, 7036).

