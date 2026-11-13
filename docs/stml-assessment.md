# Оценка STML и адаптация под «ИИ-защитник»

> Рабочая оценка, не норматив. Основана на текущем состоянии репозитория
> (2026-11-13): user-mode прототип, F19 закрыт, F11/R1/R4 открыты,
> `run_all` 29/29, 650 тестов, `docs_consistency` частично красный.

## 1. Вердикт

**Направление STML выбрано правильно, но дорожная карта переразмерена для
текущей стадии проекта.** Это хорошая архитектурная карта на 9–12 месяцев, а не
на «2–3 недели S0 + 3–4 недели S1».

Главные проблемы:

1. **STML нельзя строить независимо от агента.** В текущем агенте нет
   fleet-протокола: enrolment, policy pull, report queue, signed policy,
   server trust. `core/ipc.py` — локальный JSON-RPC, а не транспорт до сервера.
2. **Слишком много инфраструктуры для MVP:** NATS, Tauri, K8s, HSM, gRPC+REST
   одновременно. Для 100 агентов это преждевременно.
3. **Не определён корень доверия:** кто владеет корневым ключом, как проходит
   key ceremony, backup, ротация, кворум, отзыв при компрометации.
4. **S4 (Learning) поставлен слишком рано и оптимистично.** Сейчас ML — офлайн-
   скрипты; нет приёма телеметрии, курирования, песочницы, регрессии и
   подписанной доставки.
5. **Метрики S1–S10 частично не про STML:** S9/S10 — про драйвер и агент;
   S7 «0 % API» конфликтует с enrolment.

**Рекомендуемый MVP:** STML-0 (контракты) + STML-1 (Fleet Core) +
STML-2 (Trust, dev-HSM) + минимальный GUI/TUI. Без NATS, K8s, Tauri, auto-ML.
Оценка: **10–14 недель силами 1–2 инженеров** при условии, что агент стабилен.

## 2. Что в карте хорошо

- **STML — trust boundary вне агента.** Это правильный принцип; сервер не
  должен запускаться на хосте, который защищает.
- **Разделение backend/GUI и HSM только на backend** — верно.
- **Rust для API/флота + Python для ML** — соответствует уже сделанному
  Rust-порту F19 и офлайн-ML.
- **PostgreSQL + S3/MinIO** — правильная база; SQLite не для флота.
- **Модульность T0–T3, capability-based, отключение по умолчанию** — хорошая
  модель, если не превращается в микросервисы на старте.
- **Human-approval, audit chain, подпись пакетов** — обязательны и правильно
  поставлены в S2.
- **Приоритетные очереди P0–P3, идемпотентность, offline mode** — правильная
  «кровеносная система».
- **Честные потолки** (99,9 %, компрометация STML, цикл обучения) — хорошо.

## 3. Что не подходит проекту сейчас

### 3.1. STML опережает готовность агента

Сейчас у агента есть:

- локальный JSON-RPC (`core/ipc.py`), self-protect, ModelPack, updater;
- нет fleet-id/enrolment, mTLS, policy pull, report spool, server-signed policy,
  remote kill-switch.

STML S1/S5 требуют **изменений агента**, а не только сервера. Без этого S1
получится «склад с API», к которому некому подключаться.

### 3.2. NATS/K8s/Tauri — преждевременно

- **NATS JetStream** для 100 агентов не нужен: PostgreSQL outbox + polling/SSE
  закрывает S1/S5. NATS — после load-теста на 1k+ агентов.
- **K8s** — после появления реального парка; Docker Compose + systemd
  достаточно для MVP.
- **Tauri** — не обязателен для trust boundary: безопасность даёт backend
  (authn/authz/mTLS), а не тип GUI. Для MVP быстрее браузерный админ с mTLS/
  SSO/TOTP + TUI. Tauri — если нужен десктоп-клиент.
- **gRPC + REST одновременно** — двойная поверхность. Для MVP REST/OpenAPI;
  gRPC — только для телеметрии, когда упрётся.

### 3.3. HSM: одного YubiHSM недостаточно

YubiHSM — хороший минимум, но это **single point of failure** и один ключ.
Нужны:

- root ключ offline/HSM, не на backend;
- backup HSM или quorum (2-of-3);
- key ceremony и запись в audit;
- ротация с overlap;
- отзыв при компрометации и перевыпуск флота;
- отдельные ключи для драйвера/моделей/политик/обновлений.

SoftHSM — только dev; это прямо зафиксировать в конфиге и CI.

### 3.4. Learning pipeline не готов к S4

Нет:

- приёма и валидации телеметрии;
- дедупликации/курирования/разметки;
- песочницы для детонации;
- воспроизводимого обучения и регрессии;
- privacy/retention/DPIA;
- защиты от отравления на уровне данных.

S4 «4–6 недель» реалистичен только как **ручной офлайн-цикл** (кейсы → retrain →
регрессия → подпись), без автоматического флота.

### 3.5. API «всё выключено» ломает enrolment

Если все API выключены, новый агент не может зарегистрироваться. Нужно:

- **deny-by-default**, но с явно включённым bootstrap/enrolment endpoint;
- one-time enrolment token + Ed25519 ключ агента;
- после enrolment — mTLS-сертификат/короткоживущий токен;
- health и enrolment — единственные публичные endpoints.

### 3.6. Метрики S1–S10 нужно переписать

| Метрика | Проблема | Как исправить |
|---|---|---|
| S1 99,9 % | нет HA/on-call в MVP | старт 99,5 %, затем 99,9 % с error budget |
| S2 p95 ≤2 с | ок | оставить, но измерить на 1k агентов |
| S3 7 дней | ок для canary | привязать к проценту флота и FP-бюджету |
| S4 5 мин | зависит от polling | задать интервал pull ≤60 с и jitter |
| S7 0 % API | конфликт с enrolment | «deny-by-default + bootstrap» |
| S8 7 дней | люди/песочница/регрессия | старт 30 дней, затем сокращать |
| S9/S10 | это агент/драйвер | перенести в v9.1, не в STML |

Добавить: S11 report durability/ACK, S12 policy rollout success, S13 audit
verification, S14 backup RTO/RPO, S15 key compromise recovery.

## 4. Адаптированная архитектура MVP

```
┌────────────────────────────────────────────────────────────┐
│ STML Core (один Rust-сервис, axum)                         │
│  - authn/authz, enrolment, fleet registry                  │
│  - policies, rollout, kill-switch                          │
│  - report ingest (idempotent), audit                       │
│  - trust: dev Ed25519 → HSM later                          │
├────────────────────────────────────────────────────────────┤
│ PostgreSQL (метаданные, outbox, audit)                     │
│ Local object store (пакеты/модели) → S3/MinIO позже        │
└────────────────────────────────────────────────────────────┘
        ▲ REST/JSON + Ed25519/mTLS          ▲ TUI/браузер
        │                                   │
   агенты (pull)                       оператор (read-only + approve)
```

- **Один процесс**, но модули внутри с явными границами; не микросервисы.
- **Postgres outbox** вместо NATS.
- **REST + JSON** для MVP; gRPC — позже.
- **TUI + минимальный web-админ**; Tauri — после пилота.
- **SoftHSM/dev-ключ** в dev; production HSM — отдельный gate.

## 5. Адаптированные этапы

### STML-0. Контракты и угрозы (2–3 недели)

- `schemas/stml/v0`: enrolment, heartbeat, inventory, policy, report, command,
  ack, error.
- Переиспользовать `schemas/v3` для Event/Verdict/Action.
- Определить ключевую иерархию: root → policy/model/driver keys.
- Threat model STML: компрометация сервера, подмена policy, отравление,
  replay, MITM, stolen agent key.
- **Gate:** спецификация + threat model + 5 контрактных тестов; без кода
  сервера.

### STML-1. Fleet Core MVP (4–6 недель)

- Rust axum + PostgreSQL.
- Enrolment: one-time token → agent Ed25519 key → short-lived session.
- Heartbeat/inventory; статус, версия, capabilities.
- Policy CRUD, версии, diff, dry-run; signed policy (dev key).
- Rollout canary 1→10→100 %, halt, rollback.
- Report ingest: idempotency `report_id`, P0–P3 queues, ACK, spool.
- Kill-switch: rule/model/agent; TTL, ACK, audit.
- Audit chain + export.
- **Gate:** 100 агентов, p95 heartbeat ≤2 с, kill-switch ≤5 мин, 0 потерь P0,
  canary rollback, все API deny-by-default кроме bootstrap/health.

### STML-2. Trust Service (3–4 недели)

- Отдельный процесс/контейнер, доступ к HSM.
- SoftHSM dev; production HSM — после gate.
- Подпись policy/model/driver packs; проверка на сервере и агенте.
- Human approval: diff, approve, audit; 2-person для драйвера.
- Key rotation/revocation; backup/restore ключей.
- **Gate:** подпись/проверка, отзыв, ротация, audit verify, restore.

### STML-3. Learning offline (6–8 недель)

- Сбор кейсов opt-in, PII-фильтр, retention.
- Курирование/разметка, дедуп, песочница.
- Офлайн-retrain, holdout, регрессия, signed model pack.
- Никакого auto-deploy; только human-approved rollout.
- **Gate:** TPR на свежем holdout растёт, FP не растёт, откат 100 %.

### STML-4. Scale/HA (4–6 недель)

- NATS/Kafka — только если load-тест показал предел Postgres.
- K8s/Helm, multi-tenant, air-gapped bundles, SIEM.
- **Gate:** 1k+ агентов, HA, restore, pen-test.

## 6. Что добавить в карту (пропущено)

1. **Agent-side prerequisites**: fleet-id, enrolment, policy agent, report
   spool, signed policy verification, remote kill-switch.
2. **Key ceremony/quorum/backup**: без этого HSM — театр.
3. **Supply chain**: SBOM, reproducible builds, signed containers, CVE scan,
   pinning.
4. **Privacy/legal**: 152-ФЗ/GDPR, DPIA, consent, retention, deletion,
   data residency.
5. **DR/BCP**: RTO/RPO, restore-тест, «STML скомпрометирован» runbook,
   массовый отзыв агентов.
6. **API versioning/compat**: `stml/v0`, capability negotiation, deprecation.
7. **Clock/replay**: nonce + timestamp + server time, skew limit.
8. **Rate limiting/anti-DDoS**: per-agent и per-IP, backoff/jitter.
9. **Load/chaos/security testing**: 1k агентов, kill server, disk full,
   key rotation, MITM, stolen token.
10. **Tenant isolation**: даже в single-tenant MVP заложить `tenant_id`.

## 7. Решения, которые нужно принять сейчас

| # | Вопрос | Рекомендация |
|---|---|---|
| 1 | Строить STML до закрытия F11/R1/R4? | Нет; параллельно только контракты STML-0 |
| 2 | MVP-транспорт | REST/JSON + Postgres outbox; gRPC/NATS позже |
| 3 | GUI | TUI + web-админ; Tauri позже |
| 4 | HSM | SoftHSM dev; production — YubiHSM/CloudHSM + quorum |
| 5 | Enrolment | one-time token + Ed25519; mTLS после |
| 6 | Learning | только офлайн, human-approved; без auto-deploy |
| 7 | Multi-tenant | single-tenant MVP, `tenant_id` в схеме |
| 8 | Air-gapped | проектировать offline-подпись, не строить сейчас |

## 8. Что делать в ближайшие 2 недели

1. Зафиксировать **STML-0**: схемы, key hierarchy, threat model, API-контракты.
2. Добавить в агент **fleet-id + enrolment + report spool** (минимально).
3. Поднять **Postgres + axum skeleton** с health/enrolment (deny-by-default).
4. Написать **contract tests** агент↔сервер, без NATS/HSM.
5. Не строить S4, пока нет данных и песочницы.

## 9. Итог

STML как продукт **имеет смысл**, но его нельзя начинать с инфраструктуры
(NATS, K8s, Tauri, HSM). Начинать нужно с **контрактов и fleet-core**, иначе
получится сервер, который не с кем соединить. Полная карта S0–S8 — это
**9–12 месяцев** для команды, а не 4–5; MVP управления и доверия — **10–14
недель** после стабилизации агента.
