# Agent Connector (`stml-agent-bridge`) — контракт

> Python-адаптер между текущим агентом (`core/ipc.py`, `*.jsonl`) и STML.
> Ядро агента не меняется. Pickle локализован в `AgentClient`.

## 1. Внутренний JSON-RPC (localhost)

- Транспорт: TCP `127.0.0.1:<dynamic>`, line-delimited JSON-RPC 2.0, лимит строки 1 MiB.
- Порт: `0` (ОС выбирает), lock-файл: `{"pid","port","exe_hash"}`.
- Если lock указывает на живой процесс с тем же `exe_hash` — `AlreadyRunning`, второй коннектор не стартует.
- Методы: `ping`, `status`, `heartbeat`, `inventory`.

Пример:

```json
{"jsonrpc":"2.0","id":1,"method":"status","params":{}}
{"jsonrpc":"2.0","id":1,"result":{"agent_id":"...","heartbeat":{...},"spool_p0":0}}
```

## 2. Чтение агента

- Основной путь: `core.ipc.RpcClient` (pickle) → `health`, `stats`, `immutable_check`.
- Fallback: `*.jsonl` через `JsonlTailer`; offset в state-файле, partial line не потребляется, ротация (inode/размер) сбрасывает offset, невалидный JSON пропускается и считается.
- Таймаут RPC: 2 с; при ошибке — `AgentUnavailable` → heartbeat `offline`/`source=files`.

## 3. Буфер и доставка

- SQLite outbox: `report_id UNIQUE`, priority, attempts, next_attempt_at, acked.
- P0 не вытесняется; лимит 10k строк, purge старше 7 дней.
- Retry: экспоненциальный backoff 1→2→4→…→300 с.
- Транспорт: `ConsoleTransport` (VS1), `MemoryTransport` (тесты), `HttpTransport` (`POST /v0/reports`, ack).
- При падении сервера P0 остаётся в буфере и досылается после восстановления.

## 4. Идентичность

- `agent_id`, `connector_id` генерируются один раз и сохраняются в state-файле.
- `tenant_id` — из конфигурации.
- Authkey: `AIDF_AUTHKEY` (hex) или `os.urandom(32)` (ephemeral, как в `aidf_service.py`).

## 5. CLI

```powershell
python -m stml.connector run --once --console --data-root <dir>
python -m stml.connector run --console --agent-address <pipe/socket> --token <viewer-token>
python -m stml.connector contract   # JSON schema Heartbeat
```

## 6. Ограничения S0.1a

- Подпись пакета/сообщений — S0.1b.
- mTLS — S2/S3.
- `enrolment` — S1 (в S0.1a сервер не требуется, VS1 = консоль).
- `get_inventory`/`get_policy_state` отсутствуют → fallback.
