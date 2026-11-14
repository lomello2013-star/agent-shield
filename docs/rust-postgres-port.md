# Rust/axum + PostgreSQL — каркас и план порта

> Статус: **scaffold**, не parity. Python reference остаётся рабочим.
> Каркас: `rust/stml-server/` (axum `/health`, `/v0/agents` placeholder;
> `migrations/0001_init.sql`).

## 1. Что уже есть

- `Cargo.toml`: axum, tokio, serde, tracing; `sqlx` — optional feature
  `postgres`.
- `src/main.rs`: `/health`, `/v0/agents` (пустой placeholder), bind
  `STML_BIND` (default `127.0.0.1:8080`).
- `migrations/0001_init.sql`: agents/reports/policies/approvals под PostgreSQL.
- **Сборка не проверена:** `cargo check` не смог скачать `axum` — DNS
  `index.crates.io` недоступен в текущем окружении. Это внешний сетевой блокер,
  не ошибка кода.

## 2. Принцип порта

- `stml/v0` — контракт; Python и Rust реализации должны проходить одни и те же
  контрактные тесты (HTTP-level).
- Не портировать `core/` агента и STML одновременно.
- Пока агент Python, Rust-сервер общается с коннектором по HTTP; коннектор
  скрывает язык агента.
- Сначала PostgreSQL-адаптер + parity для S0/S1 (agents/enrol/heartbeat/reports),
  затем trust/learning.

## 3. Этапы порта

1. **P0:** `sqlx` pool, миграции, `Store` trait; health/readiness.
2. **P1:** agents/enrol/heartbeat/inventory/reports; Ed25519 verify.
3. **P2:** policies/rollouts/approvals; tenant filter.
4. **P3:** trust keys/CRL/audit; learning.
5. **P4:** GUI static, mTLS, metrics/SLO.
6. **P5:** contract tests Python↔Rust, нагрузка 1000, parity report.

## 4. Решения

- **Rust target:** axum 0.8 + tokio; sqlx/Postgres (feature).
- **DB:** PostgreSQL 16+; JSONB; RLS per tenant.
- **Auth:** Ed25519 для агентов, bearer для операторов; mTLS — на уровне TLS.
- **Parity:** Python reference не удаляется до прохождения контрактных тестов.

## 5. Блокеры

- Нет сети к crates.io → сборка не проверена.
- Нет PostgreSQL-сервера → интеграционные тесты не запускались.
- Нет Node/npm → Tauri не начат.

## 6. Следующий шаг

После появления сети/Postgres:
```powershell
cargo check --manifest-path rust\stml-server\Cargo.toml
cargo check --manifest-path rust\stml-server\Cargo.toml --features postgres
$env:DATABASE_URL="postgres://..."
sqlx migrate run --source rust\stml-server\migrations
```
