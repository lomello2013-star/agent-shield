# Multi-tenant (S8)

## 1. Текущая модель

- **Один STML-сервер = один тенант** (`ServerConfig.tenant_id`).
- В хранилище добавлен `tenant_id` для `agents`, `reports`, `policies`,
  `approvals`; выборки фильтруются по тенанту.
- Ключи, audit, модели — общие для инсталляции (per-tenant keys — следующий шаг).

## 2. Что проверено

- `test_tenant_isolation_policies_agents_approvals`: два тенанта, политики/агенты
  не пересекаются; approval одного тенанта не виден другому.
- API-уровень: `/v0/agents`, `/v0/policies`, `/v0/approvals` фильтруются по
  `config.tenant_id`.

## 3. Что не сделано

- **Маршрутизация по токену/тенанту**: один сервер обслуживает один tenant_id.
  Для >1 клиента нужен либо отдельный инстанс/БД, либо tenant-claim в токене.
- **RLS (PostgreSQL)** — не реализован (SQLite).
- **Per-tenant ключи/HSM/audit** — общие.
- **GUI tenant switcher** — отсутствует.

## 4. Решение S8

Single-tenant per deployment; `tenant_id` в схеме и фильтрация — база для
multi-tenant. Полная изоляция (RLS/tenant-claim) — отдельный этап после
PostgreSQL.
