# Phase A — пошаговая инструкция для оператора

> Цель: STML видит **реальный** агент (read-only). Политики/команды ещё не
> управляются — это Phase B. Пилот только в доверенной сети.

## 0. Предусловия

- Windows, Python 3.12, репозиторий `D:\ИИ защитник Вектор-защитник`.
- Права администратора (служба агента, задачи).
- Агент **не** должен быть в production-режиме; F11/R1/R4 ещё не закрыты.

## 1. Проверить/установить службу агента

```powershell
# elevated PowerShell
$repo = "D:\ИИ защитник Вектор-защитник"
$py = (Get-Command python.exe).Source
New-Service -Name AIDefender `
  -BinaryPathName "`"$py`" `"$repo\scripts\aidf_service.py`"" `
  -StartupType Automatic -DisplayName "AIDefender"
Start-Service AIDefender
Get-Service AIDefender
```

Если служба уже стоит — просто `Start-Service AIDefender`.

Проверить данные:

```powershell
Get-ChildItem C:\ProgramData\AIDefender
# authkey.hex, admin.token, operator.token, audit\, spool\
```

Токены не выводить в чат/логи.

## 2. Запустить STML-сервер

В отдельном терминале (не в службе):

```powershell
cd "D:\ИИ защитник Вектор-защитник"
python -m stml.server run --port 8080 `
  --db "$env:ProgramData\AIDefender\stml\server.sqlite3" `
  --trust-dir "$env:ProgramData\AIDefender\stml\trust"
```

Сервер запишет токены в `C:\ProgramData\AIDefender\stml\tokens.json` с ACL и
напечатает **только путь** (не сами токены). Прочитай `tokens.json` из-под
своего пользователя; не вставляй токены в чат/логи.

Проверка:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
```

## 2a. Автозапуск сервера

```powershell
# elevated
& "D:\ИИ защитник Вектор-защитник\scripts\install_stml_server_task.ps1"
Get-ScheduledTask -TaskName "AIDefender-STML-Server"
```

Задача `SYSTEM` копирует `run_server.cmd` в `C:\ProgramData\AIDefender\stml`
(ASCII-путь) и работает из короткого пути репозитория; DB/trust/tokens должны
быть доступны SYSTEM (ACL).

## 3. Настроить и запустить sidecar

Открой `scripts\run_stml_connector.cmd`; при необходимости поправь
`STML_SERVER_URL` (по умолчанию `http://127.0.0.1:8080`).

Задай одноразовый enrolment token в текущей сессии:

```powershell
$env:STML_ENROL_TOKEN = "<enrol_token>"
$env:STML_TENANT = "default"
& "D:\ИИ защитник Вектор-защитник\scripts\run_stml_connector.cmd"
```

Ожидаемо:

```json
{"connector":"running", ...}
{"tenant_id":"default", ..., "heartbeat":{...,"status":"healthy"}, "inventory":{"os":"windows",...}}
```

Если `status=offline` — проверь `AIDF_ADDRESS` (named pipe), токен и authkey.

## 4. Проверить в STML

```powershell
# viewer token из шага 2
$viewer = "<viewer_token>"
Invoke-RestMethod http://127.0.0.1:8080/v0/agents -Headers @{Authorization="Bearer $viewer"}
```

Или открой `http://127.0.0.1:8080/ui/` → Settings → viewer token → Fleet.
Должен быть один агент, `status=healthy`, `os`, `arch`, `policy=—` (Phase A не
управляет политиками).

## 5. Поставить sidecar в автозапуск

```powershell
# elevated
& "D:\ИИ защитник Вектор-защитник\scripts\install_stml_connector_task.ps1"
Get-ScheduledTask -TaskName "AIDefender-STML-Connector"
```

Задача работает от SYSTEM, читает те же файлы в `C:\ProgramData\AIDefender`.
Серверная задача — `AIDefender-STML-Server` (`install_stml_server_task.ps1`).

## 5a. Если задача не стартует

- `Get-ScheduledTaskInfo` → `LastTaskResult`.
- Проверить `C:\ProgramData\AIDefender\stml\server.run.log` (без токенов).
- SYSTEM должен иметь ACL на `server.sqlite3`, `tokens.json`, `trust/`.
- Использовать полный путь к `python.exe` в `run_server.cmd` / `run_connector.cmd`.

## 6. Остановка/откат

```powershell
Stop-ScheduledTask -TaskName "AIDefender-STML-Connector"
Unregister-ScheduledTask -TaskName "AIDefender-STML-Connector" -Confirm:$false
# STML-сервер — Ctrl+C в его терминале
```

Службу агента не удаляй, если она нужна.

## 7. Что проверить и записать

- [ ] heartbeat `healthy`, source `rpc`.
- [ ] inventory `os/arch/version` не `unknown`.
- [ ] `immutable_ok=true`.
- [ ] sidecar переживает перезапуск (задача).
- [ ] токены только в `C:\ProgramData\AIDefender`, ACL.
- [ ] записать результат в `artifacts/stml_phase_a.json` (создать вручную).

## 8. Ограничения Phase A

- Только чтение: policy/rollout/isolate **не** доходят до агента.
- F11/R1/R4 не закрыты; это не production.
- `authkey.hex`/токены — файлы; production: DPAPI/TPM/secret store.
- Не использовать admin-токен в коннекторе; только operator.

## 9. Безопасность после проверки

- Ранее `server.boot.log` содержал токены в открытом виде — он удалён.
- Токены теперь пишутся в `tokens.json` с ACL; сервер печатает только путь.
- Если токены попадали в логи/скриншоты — **перевыпусти** их (удали `tokens.json`
  и перезапусти сервер), затем обнови GUI/sidecar.

