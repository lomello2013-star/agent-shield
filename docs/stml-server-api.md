# STML Fleet Core API (S1 MVP)

> Реализация: `stml/server/app.py` (Python stdlib HTTP, reference), хранилище —
> `stml/server/store.py` (SQLite, single-tenant). Rust/axum — production-порт
> (см. `docs/stml-decisions.md`, D-21).

## 1. Аутентификация

| Тип запроса | Способ |
|---|---|
| Агент: heartbeat/inventory/reports | Ed25519 подпись тела (`X-STML-Signature`, base64) + `agent_id`; pubkey — при enrolment |
| Оператор: чтение | `Authorization: Bearer <viewer_token>` |
| Оператор: kill-switch | `Authorization: Bearer <admin_token>` |
| Enrolment | одноразовый `enrolment_token` в теле |

Replay: `nonce` одноразовый (`nonces`), `sent_at` ±300 с.

## 2. Эндпоинты

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/health` | живость |
| GET | `/` | read-only Dashboard (ввод viewer token) |
| POST | `/v0/enrol` | одноразовый token + pubkey → `agent_id` |
| POST | `/v0/heartbeat` | подписанный `Heartbeat`; ответ `{ok, isolated}` |
| POST | `/v0/inventory` | подписанный `Inventory` |
| POST | `/v0/reports` | `{reports:[Report]}` → `{acked:[report_id]}` |
| GET | `/v0/agents` | список агентов (viewer) |
| GET | `/v0/agents/<id>` | агент (viewer) |
| POST | `/v0/agents/<id>/isolate` | `{isolated: bool}` (admin) |
| GET | `/v0/audit/verify` | проверка audit-цепочки (admin) |
| GET | `/v0/policies` | список policy-версий (viewer) |
| POST | `/v0/policies` | подписанная policy (admin, `policy_pubkey`) |
| POST | `/v0/policies/<id>/<ver>/dry-run` | `{agent_ids?}` → would_change (viewer) |
| POST | `/v0/rollouts` | `{policy_id,version,percent}` (admin) |
| GET | `/v0/rollouts/<id>` | статус + затронутые агенты (viewer) |
| POST | `/v0/rollouts/<id>/halt` | остановить (admin) |
| POST | `/v0/rollouts/<id>/rollback` | вернуть старые версии (admin) |

## 2a. Policy signing

- Канонический payload: `{"policy_id","version","channel","content"}` JSON sorted.
- Подпись Ed25519; `key_id` = sha256(pubkey)[:16]; сервер проверяет `policy_pubkey` из конфигурации.
- `dry-run` не меняет состояние; `rollout percent` выбирает первых N агентов (детерминированно), сохраняет `old_version` для rollback.
- `halt` не откатывает; `rollback` восстанавливает `old_version`.

## 3. Пример heartbeat

```json
{
  "schema_version": "stml/v0",
  "tenant_id": "default",
  "agent_id": "<uuid>",
  "connector_id": "<uuid>",
  "message_id": "<uuid>",
  "sent_at": "2026-11-14T10:00:00+00:00",
  "nonce": "<hex>",
  "status": "healthy",
  "health": {},
  "source": "rpc"
}
```

Подпись: Ed25519 по **точным байтам тела**, base64 в `X-STML-Signature`.

## 4. Хранилище (SQLite MVP)

`agents`, `reports`, `audit`, `enrol_tokens`, `nonces`. Audit — hash-chain
(`prev_hash` + canonical body). Postgres-адаптер — S1.5, интерфейс `Store`
совместим.

## 5. Ограничения S1 MVP

- Policy CRUD / rollout / canary — слой B, ещё не реализованы.
- mTLS и отзыв сертификатов — S2.
- Rust/axum — production-порт, после стабилизации протокола.
- Dashboard — read-only, без мультитенантности.
