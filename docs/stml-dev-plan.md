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

## Фаза 2 — Trust Service (S2)

1. Prod HSM + quorum (2-of-3 / 2-of-2 — решение до S2).
2. Миграция ключей S0→prod с overlap (`key_id`).
3. Подпись/проверка пакетов (Ed25519).
4. Human-approval (diff/approve/audit), SLA 48 ч.
5. Audit log append-only + экспорт SIEM.
6. Отзыв ключа ≤24 ч; ротация с overlap; backup/restore.
7. Тесты #7–#10 (сертификат, MITM, отзыв, инъекция policy).
8. Key ceremony (`docs/key-ceremony.md`).
9. Immutable guards в CI.
10. SoD: Admin ≠ approve, Approver ≠ kill-switch.
- **Гейт S2:** prod HSM+quorum; миграция; тесты #7–#10; отзыв ≤24 ч; audit verify 100%; restore RTO ≤1 ч; key ceremony; threat model; SoD.

---

## Фаза 3 — Терминал GUI (S3)

1. Tauri mTLS (`reqwest` + client cert + DPAPI) — по результату спайка S0.1b.
2. Экраны: Dashboard, Fleet, Agents, Policies, Rollout, Trust/Approvals, Reports, Incidents, Learning, Modules, Ops, Settings (API).
3. Включение/выключение API (deny-by-default).
4. Управление модулями (вкл/выкл, версии, права, изоляция).
5. Dry-run по умолчанию; GUI kill-switch (RBAC, Admin, подтверждение); human-approval из GUI.
6. RBAC — одна матрица «роль × ресурс × GUI/API»; SoD.
7. GUI не хранит секретов (только mTLS-сертификат в OS-хранилище).
8. TUI; тренинг оператора (`docs/operator-training.md`); S18/S19.
- **Гейт S3:** оператор видит флот, dry-run, раскатка, откат, approve; GUI kill-switch; RBAC+SoD; TUI; GUI без секретов; допуск к production — после тренинга.

---

## Фаза 4 — Learning Pipeline (S4)

1. Приём opt-in телеметрии: анонимизация (хеширование + удаление raw + k-anonymity), PII-фильтр, retention.
2. Курирование/разметка: `case_id`, SLA разметки, ≥500 кейсов/итерацию, дедуп.
3. Реестр моделей + версии + метрики.
4. Песочница + replay-буфер.
5. Офлайн-retrain (LoRA/fine-tune) в изолированной ВМ.
6. Регрессия: TPR@FPR, FP-бюджет, holdout (отдельно от API).
7. Подпись + staged rollout + dual-slot откат ≤15 мин.
8. Внешние модели-советники (без подписи).
9. Baseline с методикой (`docs/s4-baseline.md` + скрипт + датасет + seed).
- **Гейт S4:** телеметрия анонимизирована; оператор подтверждает выборку; модель обучается/регрессирует/подписывается; no-regression; dual-slot ≤15 мин; `MODELS_TRAIN_ON_DEVICE=False` (CI).
- **DPIA — в финале** (не блокирует S4.1; юрист привлекается перед production/масштабированием).

---

## Фаза 5 — Масштаб транспорта (S5)

1. NATS JetStream для >1k агентов (или Kafka — по критерию ADR D16).
2. Pull + опциональный push (gRPC stream).
3. Replay-защита (nonce + timestamp + skew limit).
4. Offline 7 дней.
- **Триггер:** 800 агентов при работающем S1 → подготовка S5; инцидент S1 (p95 >2 с на 500) — эскалация.
- **Гейт S5:** P0 не теряется (1k); дубликаты 0; offline 7 дней; kill-switch ≤5 мин на 1k; replay.

---

## Фаза 6 — Ops и наблюдаемость (S6)

1. SLO S1–S19 + error budget + дашборды + алерты.
2. Watchdog (три линии: 1 / 2a Prometheus **отдельный хост** / 2b SIEM / 3 облачный uptime или локальный пробер).
3. `windows_exporter`.
4. Матрица «метрика → порог → алерт → действие».
5. OTel-трейсы `trace_id` от агента до GUI.
6. Backup + restore (тест).
7. Incident runbook + план коммуникации.
8. Pen-test STML (CVSS ≥7.0 — исправлены до приёмки).
- **Гейт S6:** SLO в целях; watchdog ≤60 с; трейс полный; backup восстановлен; runbook; pen-test (CVSS критерий).

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
