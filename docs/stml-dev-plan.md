# STML — план разработки (от начала до конца)

> Исполняемый чек-лист. Работаем **по факту**: без фиксированных бюджета и сроков;
> каждый шаг закрывается по готовности, а не по календарю.
> Источник правил и гейтов — [docs/stml-roadmap.md](stml-roadmap.md) (v1.3).

**Легенда статусов:** `[done]` выполнено · `[next]` ближайший шаг · `[todo]` в очереди.

---

## Фаза 0 — Фундамент и коннектор (S0)

### 0.1 S0.0a — Быстрый скан `[done]`
- [x] Карта источников `core/ipc.py` (10 RPC, роли, pickle, authkey, 1 MiB).
- [x] Семантика RPC по коду (`kill_switch`=rule, `shutdown`=агент, `quarantine`=объект, `immutable_check`=fingerprint).
- [x] Источник authkey (`AIDF_AUTHKEY` env → `os.urandom(32)`).
- [x] Файлы fallback (`audit/chain.jsonl`, `quarantine.jsonl`, `spool/events.jsonl`).
- [x] Rust-порт выведен из области S0–S3.
- **Артефакт:** [docs/stml-source-inventory-quick.md](stml-source-inventory-quick.md).

### 0.2 S0.0b — Детальная карта и схема `stml/v0` `[done]`
1. [x] Поля/форматы/частота источников (`health`, `stats`, `*.jsonl`).
2. [x] Схема `stml/v0` (enrolment, heartbeat, inventory, policy, report, command, ack, error).
3. [x] Маппинг 5 ключевых RPC/операций: enrolment, heartbeat, inventory, report, ack.
4. [x] Механика чтения `*.jsonl`: offset в state, partial line, ротация, дедуп по `report_id`.
5. [x] `report_id` генерирует коннектор (persistent в SQLite).
- **Артефакты:** `stml/contracts/v0.py`, `docs/stml-v0-schema.md`, `docs/stml-agent-bridge.md`.

### 0.3 S0.0c — Решения и соглашение `[done]`
1. [x] ADR D15 (pickle→JSON) — `docs/adr.md`.
2. [x] ADR D14 (multi-tenant) — черновик.
3. [x] Решение по разрыву контракта (fallback + серверный флаг).
4. [x] Соглашение с владельцем агента (≥2 недели) — зафиксировано.
- **Артефакты:** `docs/s0-decision.md`, `docs/stml-decisions.md`, `docs/adr.md`.

### 0.4 S0.1a — Коннектор-минимум → VS1 `[done]`
1. [x] Python-клиент к `core/ipc.py` + внутренний JSON-RPC (динамический порт + lock PID + hash).
2. [x] Fallback через `*.jsonl`.
3. [x] SQLite-буфер + retry + offline mode.
4. [x] Тесты #1–#6 + #6.5 (19 STML-тестов, включая E2E и P0-выживание).
5. [x] CLI `python -m stml.connector run --once --console`.
- **Гейт VS1:** live-агент в консоли (E2E), heartbeat ≤10 с, inventory ≤30 с, P0 не теряется при падении транспорта.

### 0.5 S0.1b — Укрепление → гейт S0 `[done]`
1. [x] ACL на lock/state/spool + auth token на JSON-RPC.
2. [x] `key_id` = sha256(pubkey)[:16]; ключ и пакет подписываются/проверяются.
3. [x] Подпись пакета коннектора (`keygen` / `sign-package` / `verify-package`), проверка при старте.
4. [x] Threat model коннектора + остаточные риски (`docs/threat-model-connector.md`; принято делегированно).
5. [x] Маппинг 5 read-only RPC: `ping`, `health`, `stats`, `self_test`, `immutable_check`.
6. [ ] Стенд 4 ВМ — по факту, когда появится инфраструктура.
7. [ ] Спайки `rust-pkcs11`/`yubihsm-pkcs11`, Tauri mTLS — слой B, до S2/S3.
- **Гейт S0:** `stml/v0` заморожен; тесты 6+6.5 + signing/auth; threat model; ключ создан, пакет подписан; ADR D14/D15; `tenant_id`; 5 read-only RPC.
- **Остаток гейта:** human-подпись threat model и стенд 4 ВМ — на финальной приёмке.

---

## Фаза 1 — Fleet Core + приём отчётов + GUI read-only (S1) `[partial: functional core]`

1. [x] Реестр агентов (SQLite MVP): enrolment, heartbeat, inventory, статус, версия, `tenant_id`.
2. [x] Enrolment: one-time token → Ed25519 pubkey (отзыв сертификата — S2).
3. [x] Report ingest: идемпотентность по `report_id`, audit chain (P0–P3 — в модели).
4. [x] GUI read-only: Dashboard/Fleet/Agents (`GET /`, `/v0/agents`).
5. [x] TUI аварийный: `python -m stml.server isolate <id>` (admin token).
6. [x] TUI kill-switch ≤5 мин (тест isolate → heartbeat isolated=true).
7. [x] Policy CRUD + diff + dry-run (слой B): подпись Ed25519, `dry-run`, `would_change`.
8. [x] Rollout canary 1→10→50→100 %, halt, rollback (слой B): `start_rollout`, `halt`, `rollback`.
9. [x] p95 baseline + 100 синтетических агентов (`test_100_agents_enrolled_and_heartbeat_concurrently`).
10. [x] **S1.5:** коннектор → сервер: auto-enrol, подписанные heartbeat/inventory/reports, isolate/resume (буферизация reports).
- **Гейт S1:** 100 агентов online, p95 ≤2 с; TUI isolate; P0 идемпотентность; подпись heartbeat/inventory/reports; deny-by-default; GUI read-only. **Остаток:** policy-подпись/dry-run (B), Rust/axum port.
- **Реализация:** `stml/server/` (Python stdlib, SQLite) — reference; production Rust/axum — отдельный gate.

---

## Фаза 2 — Trust Service (S2) `[partial: dev trust]`

1. [~] Prod HSM + quorum (2-of-3 / 2-of-2) — **не сделано**; SoftHSM-dev (file backend) готов.
2. [~] Миграция ключей S0→prod — dev-ключи; миграция в HSM — при появлении HSM.
3. [x] Подпись/проверка пакетов и policy (Ed25519, `key_id`).
4. [x] Human-approval: очередь, approve/deny, SLA 48 ч (SoD).
5. [x] Audit append-only + экспорт JSON/CEF.
6. [x] Отзыв ≤24 ч, ротация с overlap, backup/restore (zip DB+trust).
7. [~] Тесты #7–#10: отзыв и policy-injection — есть; mTLS/MITM — S2 prod.
8. [x] Key ceremony — `docs/key-ceremony.md`.
9. [~] Immutable guards — в `core/policy.py`; CI-блокировка merge — процесс.
10. [x] SoD: Admin ≠ approve; Approver ≠ kill-switch (тесты).
- **Гейт S2 (dev):** SoftHSM-ключи, подпись/проверка, approval+SoD, audit export, отзыв/ротация, backup/restore — закрыто. **Prod-остаток:** HSM+quorum, mTLS, key ceremony с человеческими свидетелями.

---

## Фаза 3 — Терминал GUI (S3) `[partial: web GUI]`

1. [~] Tauri mTLS — не сделано; web GUI работает same-origin, mTLS — S2 prod/S3 Tauri.
2. [x] Экраны: Dashboard, Fleet, Policies, Approvals, Audit, Settings (`/ui/`); Reports/Incidents/Learning/Modules/Ops — следующие.
3. [~] Включение/выключение API — серверные токены; UI Settings для токенов.
4. [ ] Управление модулями.
5. [x] Dry-run + GUI isolate/resume + approve/deny (RBAC, SoD).
6. [x] RBAC в UI: viewer/admin/approver токены; SoD проверен API.
7. [x] GUI не хранит секретов: токены только в `sessionStorage`, не в файлах.
8. [ ] TUI; тренинг оператора; S18/S19.
- **Гейт S3:** флот, dry-run, rollout, approve, isolate — в web GUI; **остаток:** Tauri-обёртка, Reports/Incidents/Learning/Modules/Ops, тренинг, S18/S19.
- **Реализация:** `stml/gui/index.html` (vanilla JS, dark SOC), сервер отдаёт `/ui/`.

---

## Фаза 4 — Learning Pipeline (S4) `[partial: registry/regression]`

1. [x] Приём opt-in телеметрии: consent=true обязателен, PII-фильтр (drop raw, hash ids), retention helper.
2. [x] Курирование/разметка: `case_id`, TP/FP, holdout flag, дедуп по `case_id`.
3. [x] Реестр моделей: name/version/metrics/signature/key_id, статус staged/regressed/rejected/active.
4. [ ] Песочница + replay-буфер.
5. [~] Офлайн-retrain: внешний скрипт; сервер принимает метрики.
6. [x] Регрессия: TPR@FPR и FP-бюджет против active; no-regression gate.
7. [x] Подпись модели + staged/activate/rollback (серверный dual-slot).
8. [ ] Внешние модели-советники.
9. [ ] Baseline с методикой (ждёт данных).
- **Гейт S4 (MVP):** consent, PII-фильтр, cases, model registry, regression, signature, activate/rollback — закрыто. **Остаток:** песочница, реальный retrain, dual-slot на агенте, внешние советники.

---

## Фаза 5 — Масштаб транспорта (S5) `[partial: 1k verified]`

1. [~] NATS JetStream — адаптер есть как явная заглушка; внешний сервер/NATS не настроены. LocalBus для MVP.
2. [ ] Pull + push (gRPC stream) — pull уже есть; push отложен.
3. [x] Replay-защита (nonce + timestamp + skew).
4. [x] Offline: P0 не вытесняется, P1–P3 purge 7 дней; буфер SQLite.
- **Триггер:** 800 агентов при работающем S1 → подготовка S5; инцидент S1 (p95 >2 с на 500) — эскалация.
- **Гейт S5:** **1000 агентов, p95 111,6 мс**, enrol 9,67 с; P0 durability, offline/purge, replay. **Остаток:** реальный NATS/Kafka и push.
- **Артефакт:** `artifacts/stml_s5_load.json`; `docs/stml-transport.md`.

---

## Фаза 6 — Ops и наблюдаемость (S6) `[partial: metrics/watchdog]`

1. [x] SLO snapshot `/v0/slo`, `/metrics`, `/health`; error budget — в `docs/slo.md`.
2. [x] Watchdog: `scripts/stml_watchdog.py` (1/2a/2b/3 — процесс описан).
3. [ ] `windows_exporter` — внешний агент, не входит в сервер.
4. [x] Матрица метрика→алерт→действие — `docs/slo.md`.
5. [ ] OTel-трейсы `trace_id` — не реализованы.
6. [x] Backup + restore (тест, `stml/server/backup.py`).
7. [x] Incident runbook — `docs/runbook-stml.md`.
8. [ ] Pen-test STML — внешний gate.
- **Гейт S6 (MVP):** `/metrics`, `/v0/slo`, watchdog, backup, runbook — закрыто. **Остаток:** OTel, отдельный хост Prometheus, pen-test.

---

## Фаза 7 — Развёртывание (S7)

1. Docker Compose (малый парк) — развёртывание.
2. Helm/K8s (HA, autoscaling, rolling update).
3. Air-gapped: offline-процесс, anti-rollback, журнал USB, dual-slot, план B.
4. DR-тест на целевом стенде: Compose — backup-restore (RTO ≤1 ч); K8s — полный DR (RTO ≤4 ч, ceremony отдельно ≤24 ч).
- **Артефакты:** `docs/deploy.md`.
- **Гейт S7:** Compose; K8s; air-gapped; DR-тест на целевом стенде.

---

## Фаза 8 — Сосуществование и multi-tenant (S8)

1. Тесты с топ-3 EDR (Defender, CrowdStrike, SentinelOne).
2. Режим `compat`.
3. Матрица ОС (Windows 10/11/Server, Ubuntu/Debian/RHEL/Fedora, arm64).
4. Multi-tenant (финализация ADR D14) + tenant-изоляция (RLS).
5. SIEM-экспорт (JSON + CEF).
- **Гейт S8:** топ-3 EDR пройдены; матрица в `docs/compat.md`; tenant-изоляция проверена; SIEM; ADR D14 финализирован.

---

## Финал — DPIA и production-приёмка

1. **DPIA** (`docs/dpia-stml.md`) — юрист/DPO: retention, метод анонимизации, критерий «провален».
2. Полный проход чек-листа готовности (S0–S8).
3. Human-приёмка по каждой сквозной метрике (S1–S19, error budget, SoD, immutable guards).
4. Резервное копирование + откат-тест + runbook «STML скомпрометирован».
5. Подпись релиза и допуск операторов.

---

## Ближайшие шаги (начинаем сейчас)

1. **S0.0b** — детальная карта + схема `stml/v0` (см. Фаза 0, шаг 0.2).
2. **S0.0c** — ADR D15/D14, соглашение с владельцем агента.
3. **S0.1a** — коннектор-минимум → VS1.

**Блокеры сейчас:** соглашение с владельцем агента (S0.0c) и маппинг 5 ключевых RPC (S0.0b). Остальное — по готовности.
