# Sysmon как опция (Windows)

Sysmon не обязателен для детекции, но **без него на Windows недостижим `suspend` по PID**:
события System/Defender (7045 и т.п.) не содержат идентификатор процесса, поэтому
действие пропускается (`action_skipped`), хотя вердикт выносится.

## Что даёт Sysmon

| Событие | Поле | Использование |
|---|---|---|
| Event 1 `ProcessCreate` | `ProcessId`, `Image`, `CommandLine` | `actor.pid` / `actor.path` для правил и сдерживания |
| Event 1 | `ParentProcessId` | цепочка родитель→потомок |
| Event 3/11/22 (опционально) | сеть/файлы/DNS | расширение правил (не требуется для suspend) |

## Установка

```powershell
# от администратора
powershell -ExecutionPolicy Bypass -File scripts\setup_sysmon.ps1
# либо вручную: Sysmon64.exe -accepteula -i [config.xml]
```

Скрипт скачивает официальный Sysmon с сайта Microsoft Sysinternals в
`C:\ProgramData\AIDefender\sysmon`, устанавливает службу и печатает её статус.

## Включение источника

Служба `AIDefender` читает переменные окружения из своего ключа реестра:

```powershell
$svc = 'HKLM:\SYSTEM\CurrentControlSet\Services\AIDefender'
$envs = @((Get-ItemProperty $svc -Name Environment).Environment)
if ($envs -notcontains 'AIDF_SYSMON=1') {
    $envs += 'AIDF_SYSMON=1'
    Set-ItemProperty $svc -Name Environment -Value $envs -Type MultiString
}
Restart-Service AIDefender
```

Сервис проверяет канал `Microsoft-Windows-Sysmon/Operational`: если Sysmon не
установлен, источник **не добавляется**, а в audit пишется `sysmon_missing`
(без «тихого» падения).

## Проверка

```powershell
wevtutil gl Microsoft-Windows-Sysmon/Operational
aidfctl health     # sources: win.eventlog, win.defender, win.sysmon
aidfctl stats      # collectors: win.sysmon calls/last_query_ms
```

Ожидаемое поведение: процесс из `C:\Temp` → `WIN-EXEC-TEMP-001` → pending
confirmation с `target = PID` → `aidfctl confirm --params-file confirm.json` →
`status: executed`, процесс приостановлен.

## Без Sysmon (честное ограничение)

| Что | Результат |
|---|---|
| Детекция установки службы/Defender | работает |
| `suspend` по 7045 | `action_skipped` (нет PID) |
| `response.skipped` в `stats` | растёт |

Это ограничение **источника**, а не регрессия правила.

## Безопасность и эксплуатация

- Sysmon — драйвер ядра Microsoft Sysinternals; компонент **опциональный**.
- Ставить только из официального источника, обновлять по мере выхода версий.
- Event 1 объёмный: при необходимости ограничьте конфигом (минимум `ProcessCreate`).
- Удаление: `powershell -File scripts\setup_sysmon.ps1 -Uninstall` или `Sysmon64.exe -u`.

## Связанное

- `docs/reviews/opencode-hard-gemini-2026-11-14.md` — находка об отсутствии PID.
- `docs/operations.md` — установка/обслуживание.
- `scripts/setup_sysmon.ps1` — установка/удаление.
