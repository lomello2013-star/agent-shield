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
| Обнаружено (raw) | **9 / 11** |
| Обнаружено (с учётом атрибуции) | **8 / 11** (WIN-08 получил запоздавший `RUNKEY` от WIN-06) |
| Holdout (5) | **4 / 5** raw, **3 / 5** после атрибуции |
| Benign-контроль | 4, **1 FP**: ambient `7045` на WIN-20 (правило 007 широкое); FP 010 **устранён** |

**Обнаружены (8):** service create (007), temp exec (001), encoded PowerShell
(002), temp cmd (001), **scheduled task (006 — после 4698)**, **Run key (005 —
после Sysmon registry)**, **WMI subscription (018)**, masquerade (011).
**Пропущены (честно):**
- Downloads exec (WIN-17) — правило 016 требует `integrity.verified=false`;
  `calc.exe` подписан, поэтому это корректный non-match, а не пропуск;
- service start (WIN-18) — 7036 не даёт нового 7045;
- Defender exclusion (WIN-08) — 5007 не пришёл; его «детекция» в raw-прогоне —
  запоздавший RUNKEY.

**FP 010 устранён:** источник — `powershell.exe → CreateRemoteThread` в
`<unknown process>` (PS Direct). Правило 010 теперь требует
`object.path = *.exe`; `<unknown process>` очищается в нормализаторе. Контроль
WIN-10 больше не даёт `INJECT-010`.

**Остаточный FP** — ambient `7045` на WIN-20: Windows сам ставит службы в фоне;
правило 007 не отличает benign service install от атакующего. Нужен allowlist/
контекст (подпись, путь, родитель), иначе 007 будет шуметь на любом хосте.

Это не «5/11 эффективности»: каталог показывает **source gaps**, а не только
качество правил. Для E1–E6 нужны реальные образцы и полный 20/ОС прогон.

### Linux

20-сценарный Linux-прогон в этом срезе **не выполнялся**; существующие
`linux_*_e2e` (9 техник) и fapolicyd (10/10) — отдельные измерения, не red-team
агента. Следующий шаг — тот же каталог на Linux-VM с eBPF-агентом.

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
4698/4720/4688/1102. После закрытия 4698/registry/WMI 20-срез: raw **9/11**,
после атрибуции **8/11**, FP 1 (ambient 7045), FP 010 устранён.

