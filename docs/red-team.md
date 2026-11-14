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
