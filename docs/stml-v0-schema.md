# STML `stml/v0` — схема и маппинг

> Контракт между Agent Connector и STML-сервером. Pickle не пересекает эту
> границу. Реализация: `stml/contracts/v0.py`; тесты: `stml/tests/test_contracts.py`.

## 1. Конверт

Каждое сообщение коннектора содержит:

| Поле | Тип | Назначение |
|---|---|---|
| `schema_version` | `"stml/v0"` | версия контракта |
| `tenant_id` | str | тенант |
| `agent_id` | str | стабильный id агента (из state-файла коннектора) |
| `connector_id` | str | стабильный id коннектора |
| `message_id` | uuid | id сообщения |
| `sent_at` | datetime (UTC, tz-aware) | время отправки |
| `nonce` | str ≥8 | replay-защита |
| `signature` | str? | Ed25519 (S0.1b) |

## 2. Сообщения

| Модель | Направление | Ключевые поля |
|---|---|---|
| `EnrolRequest` | connector → server | hostname, os, arch, agent_version, connector_version, capabilities, enrolment_token |
| `EnrolResponse` | server → connector | agent_id, tenant_id, heartbeat_interval_s, inventory_interval_s, accepted |
| `Heartbeat` | connector → server | status, agent_uptime_s, health, counters, source |
| `Inventory` | connector → server | os, arch, agent_version, rules_version, model_version, capabilities, immutable_ok, source |
| `Report` | connector → server | report_id, priority (P0–P3), kind, payload, created_at, attempts |
| `Ack` | server → connector | acked[], server_time |
| `ErrorBody` | оба | code, message, retryable, detail |

## 3. Маппинг «источник агента → `stml/v0`»

| Источник | Поле `stml/v0` | Примечание |
|---|---|---|
| `health` RPC (`daemon.health()`) | `Heartbeat.health`, `Heartbeat.status` | `safe_mode` → `safe_mode`; `degraded` → `degraded` |
| `stats` RPC (`daemon.stats()`) | `Inventory.os/arch/agent_version/rules_version/model_version` | отсутствующие поля → `unknown`/`null` |
| `immutable_check` RPC | `Inventory.immutable_ok` | `{"immutable":"ok"}` → `true` |
| `spool/events.jsonl` | `Report` | priority из `priority`/`severity`, иначе P2 |
| `audit/chain.jsonl` | `Report` | P3 (audit) |
| `quarantine.jsonl` | `Report` | P3 |
| state-файл коннектора | `agent_id`, `connector_id` | генерируются один раз, persist |
| enrolment (S1) | `EnrolRequest/Response` | one-time token |

## 4. Приоритеты и `report_id`

- `P0` — инцидент; **никогда не вытесняется**.
- `P1` — alert / аномалия heartbeat.
- `P2` — feedback / обычное событие.
- `P3` — телеметрия / audit.
- `report_id` генерирует **коннектор** (persistent в SQLite). Если в записи нет `report_id` — `r-<sha256(canonical json)[:24]>`, что даёт дедуп при повторном чтении.
- Дубликаты по `report_id` игнорируются (idempotency).

## 5. Валидация

- `sent_at` обязан быть tz-aware; naive → `ValidationError`.
- `signature` — `null` до S0.1b; после — Ed25519.
- Неизвестные поля запрещены? Нет: pydantic по умолчанию игнорирует лишние; для строгого режима — `model_config = ConfigDict(extra="forbid")` (решение S0.1b).
