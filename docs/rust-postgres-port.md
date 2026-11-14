# Rust/axum + PostgreSQL — каркас и план порта

> Статус: **scaffold работает локально**, parity ещё нет. Python reference
> остаётся рабочим. Каркас: `rust/stml-server/`.

## 0. Локальная проверка (2026-11-14)

- PostgreSQL **16.16** установлен (winget), служба `postgresql-x64-16` работает.
- Dev-БД: `stml`, роль `stml` / пароль `stml` (только localhost; не production).
- Миграции `0001_init.sql` + `0002_enrol_nonces.sql` применены.
- `cargo check` / `cargo build` — успешно.
- **P1 проверен:** enrol, подписанные heartbeat/inventory/reports, `/v0/agents`;
  тест с Python-сгенерированным Ed25519-ключом.
- **P2 проверен:** policy-подпись, approvals+SoD, rollout 1→10→50→100,
  promote/halt/rollback, tenant `p2`.
- **P3 проверен:** trust keys/rotate/revoke, CRL-lite, audit hash chain,
  telemetry consent+PII-strip, cases, models + no-regression + rollback.
- **Commands проверены:** `isolate`/approval `confirm` → heartbeat `commands`,
  подписанный `/v0/commands/ack`; Rust parity с Python reference.
- **GUI проверен:** Rust отдаёт `/` и `/ui/` (тот же `stml/gui/index.html`), 200/17.6 KB.
- **P5 parity smoke:** `scripts/stml_rust_parity.py` → **14 checks**:
  health/UI/agents/policies/approvals/rollouts/models/cases/trust/CRL/audit;
  Python 8080 vs Rust 18097 — `ok:true`, `failures:[]`.
- **mTLS проверен:** rustls, client cert required; без клиентского сертификата
  TLS handshake блокируется; plain HTTP блокируется. Dev-сертификаты ECC P-256.
- **Не проверено:** CRL enforcement в Rust TLS, Tauri, write-path P5, RLS/HA,
  timestamp skew, HTTP 201 parity.

## 1. Что уже есть

- `Cargo.toml`: axum, tokio, serde, tracing, sqlx/Postgres, ed25519-dalek, spki/pem.
- `src/main.rs`: `/health`, `/v0/agents`, `/v0/enrol`, `/v0/heartbeat`,
  `/v0/inventory`, `/v0/reports`, `/v0/policies`, `/v0/approvals`,
  `/v0/rollouts`, `/v0/trust/keys`, `/v0/tls/*`, `/v0/audit/verify`,
  `/v0/telemetry`, `/v0/cases`, `/v0/models` (P1+P2+P3).
- `migrations/0001_init.sql` … `0005_learning.sql`.
- `Cargo.lock` — зафиксирован для воспроизводимости.

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

- Нет Node/npm → Tauri не начат.
- Нет parity-тестов Python↔Rust; auth/RLS/HA/backup не реализованы.
- Dev-пароль `stml` — только localhost; production — секрет-менеджер.

## 6. Следующий шаг

```powershell
$env:DATABASE_URL="postgres://stml:stml@127.0.0.1:5432/stml"
cargo run --manifest-path rust\stml-server\Cargo.toml
# /health -> {"db":"ok"}; /v0/agents -> rows
```
Далее: P4 (mTLS/CRL enforcement, GUI parity) и P5 (Python↔Rust contract tests).
