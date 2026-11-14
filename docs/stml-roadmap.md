# STML — серверный терминал управления и обучения (v0.2, улучшенная)

> **Статус:** рабочая дорожная карта, заменяет `docs/stml-assessment.md` как
> основной документ по серверной части. Полный объём (S0–S8) сохранён; порядок
> изменён так, чтобы **самые первые этапы работали с текущим агентом уже
> сейчас**, а инфраструктура (NATS, K8s, HSM, Tauri) добавлялась по мере роста.

---

## 0. Принципы

1. **STML — trust boundary вне агента.** Агент не запускает, не редактирует и
   не видит проверки, которые его оценивают.
2. **Сначала контракт, потом инфраструктура.** Не строить NATS/K8s/HSM, пока
   нет протокола агент↔сервер.
3. **Первый этап обязан работать с текущим агентом** — через его существующий
   JSON-RPC (`core/ipc.py`, `aidfctl.py`) и `schemas/v3`.
4. **Deny-by-default.** Все API выключены, кроме `health` и `enrolment`.
5. **Обучение только офлайн и только подписанное.** `MODELS_TRAIN_ON_DEVICE=False`
   не меняется; флотские веса — через сервер (ярус 2).
6. **Каждый этап — измеримый гейт**, а не «код написан».

---

## 1. Целевая архитектура (полная)

```
┌────────────────────────────────────────────────────────────────────┐
│ STML Backend (облако или локальный сервер)                        │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Fleet Manager│  │ Learning     │  │ Trust Service            │  │
│  │ (Rust/axum)  │  │ Pipeline     │  │ (Rust + HSM PKCS#11)     │  │
│  └──────┬───────┘  └──────┬───────┘  └────────────┬─────────────┘  │
│         └───────────┬─────┴───────────┬────────────┘                │
│                     ▼                 ▼                             │
│         ┌──────────────────────────────────────────────┐          │
│         │ API Gateway: REST + gRPC + mTLS, deny-by-default│       │
│         └──────────────────────────────────────────────┘          │
│         ┌──────────────────────────────────────────────┐          │
│         │ Event Bus (NATS JetStream, с S5+)            │          │
│         │ Storage: PostgreSQL + S3/MinIO               │          │
│         └──────────────────────────────────────────────┘          │
└─────────────────────────────┬──────────────────────────────────────┘
                              │ HTTPS + mTLS
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
   ┌────────────┐      ┌────────────┐      ┌────────────┐
   │ GUI (Tauri)│      │ GUI (браузер)│     │ Агенты     │
   │ оператор   │      │ оператор     │     │ (mTLS)     │
   └─────┬──────┘      └────────────┘      └────────────┘
         ▼
   ┌────────────┐
   │ TUI (SSH)  │ аварийный доступ
   └────────────┘
```

Компоненты и уровни доверия (T0–T3) — как в исходной карте, плюс:

- **T0**: API Gateway, Trust Service — human-подпись уровня C.
- **T1**: Fleet Manager, Learning Pipeline — human-подпись + авто-ревьюер.
- **T2**: встроенные детекторы — авто-ревьюер + подпись.
- **T3**: внешние ИИ оператора — только советник, без подписи и прав.

---

## 2. Этапы (полный объём, порядок под проект)

### S0 — Фундамент: контракты + агент-коннектор (1–2 недели)

**Зачем:** без протокола и bridge сервер не с кем соединить. Это то, что можно
сделать **сейчас**, параллельно с F11/R1/R4.

**Что делаем:**

- Схемы `stml/v0`: `enrolment`, `heartbeat`, `inventory`, `policy`, `report`,
  `command`, `ack`, `error` (поверх `schemas/v3`).
- Ключевая иерархия: root → policy/model/driver keys; threat model STML.
- **Agent Connector** (`stml-agent-bridge`): процесс-адаптер, который читает
  текущего агента через `core/ipc.py` (`health`, `stats`, `self_test`) и шлёт
  heartbeat/inventory на сервер. Работает с **существующим** агентом без
  изменения его ядра.
- Report spool на стороне агента: SQLite-очередь, P0 не теряется.
- Спайки (сохраняются): HSM (SoftHSM), mTLS, Tauri window, NATS pub/sub.

**Gate:** `stml/v0` заморожен; коннектор показывает live-агента в консоли;
5 контрактных тестов; threat model согласован.

### S1 — Fleet Core + приём отчётов (3–4 недели)

**Что делаем:** реестр агентов, enrolment (one-time token → Ed25519), heartbeat,
inventory, policy CRUD + diff + dry-run, rollout canary 1→10→100 %, halt,
rollback, kill-switch, report ingest с идемпотентностью `report_id`,
приоритетные очереди P0–P3, audit chain.

**Gate:** 100 агентов online; p95 heartbeat ≤2 с; kill-switch ≤5 мин; P0 потерь 0;
canary rollback работает; все API deny-by-default кроме `health`/`enrolment`.

### S2 — Trust Service (2–3 недели)

**Что делаем:** HSM (SoftHSM dev / YubiHSM+quorum prod), подпись пакетов
Ed25519, human-approval (diff/approve/audit), key ceremony, backup/restore,
ротация с overlap, отзыв ключа. Immutable guards в CI.

**Gate:** подпись/проверка, отзыв, ротация, audit verify, restore.

### S3 — Терминал GUI (3–4 недели)

**Что делаем:** Tauri (Rust+React) + аварийный TUI (ratatui). Экраны:
Dashboard, Fleet, Agents, Policies, Rollout, **Trust/Approvals**, Reports,
Incidents, Learning, Modules, Ops, Settings (API). Dry-run по умолчанию,
kill-switch одной кнопкой, human-approval из GUI.

Дизайн — в [docs/stml-gui-design.md](stml-gui-design.md) и
[docs/stml-gui-mock.html](stml-gui-mock.html).

**Gate:** оператор видит флот, делает dry-run, раскатывает, откатывает,
approve из GUI; GUI не хранит секретов; TUI работает.

### S4 — Learning Pipeline (4–6 недель)

**Что делаем:** приём opt-in телеметрии, PII-фильтр, курирование/разметка,
дедуп, песочница, реестр моделей (pe/elf/behavior/script/memory/net), внешние
модели-советники, офлайн-retrain (LoRA/fine-tune), регрессия TPR@FPR,
подпись, staged rollout. Защита от отравления, replay-буфер, no-regression gate.

**Gate:** телеметрия анонимизирована; оператор подтверждает выборку; модель
обучается/регрессирует/подписывается; внешняя модель — советник; метрики
«реально учится» в GUI; `MODELS_TRAIN_ON_DEVICE=False` соблюдается.

### S5 — Обмен отчётами и масштаб транспорта (3–4 недели)

**Что делаем:** приоритетные очереди, идемпотентность, буфер, offline 7 дней,
pull + опциональный push (gRPC stream), replay-защита (nonce+timestamp), NATS
JetStream для >1k агентов, Kafka — если интеграция.

**Gate:** P0 не теряется при kill сервера; дубликаты 0; offline 7 дней;
kill-switch ≤5 мин на 1k.

### S6 — Ops и наблюдаемость (2 недели)

**Что делаем:** SLO S1–S15, дашборды, алерты, OTel-трейсы `trace_id` от агента
до GUI, backup+restore тест, incident runbook, error budget.

**Gate:** SLO в целях; трейс полный; backup восстановлен; runbook написан.

### S7 — Развёртывание (2–3 недели)

**Что делаем:** Docker Compose (малый парк) → Helm/K8s (HA), air-gapped
bundles (подписанные, USB), гибрид облако+локально (позже).

**Gate:** Compose ≤30 мин; K8s HA + rolling; air-gapped без интернета;
`docs/deploy.md`.

### S8 — Сосуществование и multi-tenant (2–3 недели)

**Что делаем:** тесты с топ-3 EDR, режим `compat`, матрица ОС, multi-tenant
(tenant_id изолирует данные), SIEM-экспорт.

**Gate:** топ-3 EDR пройдены; матрица в `docs/compat.md`; tenant-изоляция
проверена.

---

## 3. Что добавлено/улучшено относительно исходной карты

| Область | Улучшение |
|---|---|
| Агент-интеграция | S0 добавляет **Agent Connector**, работающий с текущим JSON-RPC |
| Контракты | `stml/v0` до любого серверного кода |
| HSM | не один YubiHSM, а **root offline + quorum + backup + key ceremony** |
| API | deny-by-default + явный `enrolment`/`health` |
| Supply chain | SBOM, reproducible builds, signed containers, CVE scan |
| Privacy | 152-ФЗ/GDPR, DPIA, retention, deletion, residency |
| DR | RTO/RPO, restore-тест, «STML скомпрометирован» runbook |
| Replay/clock | nonce + timestamp + серверное время + skew limit |
| Метрики | S1–S10 пересмотрены, добавлены S11–S15 |
| GUI | инкрементально: read-only с S1, полный контроль с S3 |
| Обучение | только офлайн, human-approved; без auto-deploy |

### Метрики (S1–S15)

| # | Метрика | Цель |
|---|---|---|
| S1 | Доступность STML | 99,5 % (MVP) → 99,9 % |
| S2 | heartbeat → GUI p95 | ≤2 с |
| S3 | canary → 100 % | ≤7 дней |
| S4 | kill-switch → ACK | ≤5 мин |
| S5 | обновления STML | ≥99,9 % / откат 100 % |
| S6 | тихий отказ STML | 100 % за ≤60 с |
| S7 | API по умолчанию | 0 % (кроме health/enrolment) |
| S8 | кейс → подписанная модель | 30 дней (старт) |
| S9 | recall ревьюера на сев-дефектах | ≥95 % |
| S10 | драйвер с human-review | 100 % |
| S11 | report durability/ACK | 0 потерь P0 |
| S12 | rollout success | ≥99,9 % |
| S13 | audit verification | 100 % |
| S14 | backup RTO/RPO | ≤1 ч / ≤15 мин |
| S15 | key compromise recovery | ≤24 ч |

S9/S10 — по сути агент/драйвер, но держим их как сквозные KPI STML-контура.

---

## 4. Критический путь

```
S0 (контракты + коннектор) ──► S1 (fleet + отчёты) ──► S2 (trust)
      │                                                │
      └────────────► S3 (GUI, параллельно S1–S2) ◄─────┘
                          │
                          └──► S4 (learning) ──► S5 (scale transport)
                                    │
                                    └──► S6 (ops) ──► S7 (deploy) ──► S8 (coexist)
```

**Минимальный полезный вертикальный срез:** S0 → S1(частично) → S3(read-only)
— оператор видит живой агент и его здоровье уже после S0–S1.

---

## 5. Риск-реестр (дополнен)

- HSM несовместим с Rust → Python-обёртка PKCS#11.
- Tauri mTLS сложен → Rust-клиент + webview.
- NATS нестабилен → Kafka/Postgres outbox.
- Шторм heartbeat → приоритеты + батчинг + jitter.
- Раскатка ломает агентов → canary + halt + откат.
- Human-approval узкое место → SLA 48 ч, заместители.
- Отравление обучения → курирование, replay, holdout отдельно.
- Внешняя модель утечка → localhost, opt-in, без прав.
- Prompt-injection → нет авторитета, гейт, sandbox.
- Потеря P0 → отдельная дисковая очередь.
- Компрометация STML → offline root, quorum, mTLS, audit, runbook.
- Один ключ на всё → отдельные ключи по классам.
- Тенант-изоляция → tenant_id + row-level security с S8.

---

## 6. Открытые решения владельца

| # | Вопрос | Рекомендация |
|---|---|---|
| 1 | HSM | SoftHSM dev → YubiHSM+quorum prod |
| 2 | Event bus | Postgres outbox → NATS при >1k |
| 3 | GUI | Tauri (desktop) + TUI (SSH) + опц. браузер |
| 4 | Обучение | встроенные модели сначала, внешние-советники потом |
| 5 | Pull/push | pull + опц. push |
| 6 | Air-gapped | проектировать, строить с S7 |
| 7 | Multi-tenant | single-tenant MVP, tenant_id в схеме |
| 8 | Deploy | Compose → K8s |
| 9 | Внешние ИИ | куратор/учитель/аналитик, без подписи |
| 10 | Правовая база | 152-ФЗ/GDPR: DPIA и retention до сбора данных |

---

## 7. Следующий шаг

1. Утвердить `stml/v0` и Agent Connector (S0).
2. Зафиксировать [дизайн терминала](stml-gui-design.md).
3. S1 — Fleet Core с одним реальным агентом.
