# Runbook — STML (S6)

## 1. STML недоступен

1. Проверить `/health` и процесс (`python -m stml.server run`).
2. Watchdog: `python scripts/stml_watchdog.py --once --url ... --token ...`.
3. Если БД/файлы целы — перезапуск; иначе restore (ниже).
4. Агенты продолжают работать offline, P0 буферизуются.

## 2. Агент offline / degraded

1. `/v0/agents` — `last_seen`, `status`.
2. Проверить коннектор: lock-файл, `status` через JSON-RPC.
3. Если агент изолирован (`isolated=true`) — снять: `python -m stml.server isolate <id> --resume`.
4. Если коннектор упал — рестарт; SQLite spool досылает P0.

## 3. Компрометация STML

1. **KS-4 freeze fleet**: остановить раскатки/команды; heartbeat/отчёты оставить.
2. Отозвать ключи: `POST /v0/trust/keys/<id>/revoke`.
3. Ротировать: `POST /v0/trust/keys/<id>/rotate`.
4. Audit export в SIEM; сохранить копию.
5. Восстановить из проверенного backup на чистый хост; сменить все токены.
6. Уведомить: внутренне ≤4 ч, клиентов ≤24 ч (critical).

## 4. Backup/restore

```powershell
python -m stml.server backup --db stml-server.sqlite3 --trust-dir stml-server.sqlite3.trust --out backup.zip
python -m stml.server restore --from backup.zip --db stml-server.sqlite3 --trust-dir stml-server.sqlite3.trust
```

Проверка: `/v0/audit/verify` → `ok=true`; агенты на месте; ключи доступны.

## 5. Approval застрял

- `/v0/approvals` — статус, `decided_by`.
- SLA 48 ч; эскалация PM; заместитель approver.

## 6. Ключ недоступен / quorum

- Раскатка блокируется, алерт; **KS-4 доступен без quorum**.
- Эскалация security engineer + PM ≤1 ч.
