# STML — серверный терминал управления и обучения (v1.3, финишная к запуску)

> **Статус:** исполняемая дорожная карта. v1.2 + все правки v1.2.1 (P0→P3) + адаптация под текущий проект.
> **Область:** серверная часть STML. Агент — отдельный продукт (v9.1), драйвер — отдельный репозиторий.
> **Платформы:** облако (Compose / K8s) и локальный сервер, air-gapped.
>
> **Отличия v1.3 от v1.2 (сводно):**
> 1. **Бюджет и сроки не рассчитываются** — работаем «по факту», по готовности каждого гейта, без фиксированных сумм и недель.
> 2. **DPIA выведена из критического пути** — юрист привлекается в финале (перед production/масштабированием), не блокирует S4.1. До этого действует opt-in + анонимизация по существующему ADR D12.
> 3. **ADR перенумерованы** (разведены с уже занятыми D11/D12/D13): D14 = multi-tenant, D15 = транспорт коннектора, D16 = event bus. D11 (упаковка/обновление), D12 (телеметрия), D13 (сосуществование) — не меняются.
> 4. **Семантика RPC агента исправлена по коду**: `kill_switch` = kill правила по `rule_id`; `shutdown` = остановка агента; `quarantine` = изоляция объекта; `immutable_check` = fingerprint immutable-политики.
> 5. **Rust-порт выведен из области STML на S0–S3** — в пилоте работает только Python-агент.
> 6. **Владельцы** — таблица в `docs/owners.md` (назначение до соответствующих гейтов).
> 7. Внесены все 21 правки v1.2.1 (P0–P3), §9/§13/§15 обновлены.

---

## 0. Принципы (сквозные)

1. **STML — trust boundary вне агента.** Агент не запускает, не редактирует и не видит проверки, которые его оценивают.
2. **Сначала контракт, потом инфраструктура.** Не строить NATS/K8s/HSM, пока нет протокола агент↔сервер.
3. **Первый этап работает с текущим агентом.** `core/ipc.py` существует и работает (10 RPC, роли, pickle, authkey, 1 MiB — верифицировано). Коннектор адаптирует то, что есть.
4. **Deny-by-default.** Все API выключены, кроме health и enrolment.
5. **Обучение только офлайн и только подписанное.** `MODELS_TRAIN_ON_DEVICE=False` не меняется (эталон — `core/policy.py`; зеркало — `rust/src/policy.rs`).
6. **Каждый этап — измеримый гейт.** Гейт закрывается по слою A.
7. **Модульность с изоляцией.** Отдельные процессы, capability-based права, подпись, отключение по умолчанию, аудит.
8. **Честные границы.** 100% доступности не бывает; 100% защиты от root/админа не бывает; обучение не даёт мгновенного прироста.
9. **Никакой раскатки без подписи.**
10. **Один компонент — одна модель угроз.** Для T0/T1 — отдельные mini-threat model.
11. **Сначала инвентаризация, потом код.**
12. **Работаем по факту.** Нет фиксированных бюджета и сроков; каждый гейт закрывается по готовности, а не по календарю.
13. **Каждый гейт имеет заместителя** (RACI, A', эскалация).
14. **Протокол агента — источник истины.** `core/ipc.py` использует pickle — коннектор локализует pickle и отдаёт JSON наружу. Молчаливый «JSON-RPC» запрещён.
15. **Верификация по коду — до старта.** Расхождения фиксируются в S0.0a.
16. **Не выдавать желаемое за действительное.** Нет `suspend`/`resume` — не эмулировать. Windows — `windows_exporter`. Quorum — ≥2 HSM.
17. **Один контракт — один владелец.** `stml/v0` — security engineer + владелец коннектора.
18. **Separation of Duties.** Одна учётка — одна роль; Admin не approve; Approver не kill-switch; смена роли — два человека.
19. **Слой A — блокер, B — parallel, C — организационный.** Гейт по A; B и C — либо закрыты, либо ADR «отложено».
20. **`⚠️ УТОЧНЕНИЕ` — не «дыра», а зафиксированное решение.** (Формализация рекомендаций v1.1.)
21. **Тренинг ≠ гейт; допуск ≠ гейт.** (Формализация рекомендаций v1.1.)
22. **Целевой стенд определяет DR-тест.** (Формализация рекомендаций v1.1.)

---

## 1. Целевая архитектура (полная)

```
┌────────────────────────────────────────────────────────────────────┐
│ STML Backend (облако или локальный сервер)                        │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Fleet Manager│  │ Learning     │  │ Trust Service            │  │
│  │ (Rust/axum)  │  │ Pipeline     │  │ (Rust + rust-pkcs11)     │  │
│  └──────┬───────┘  └──────┬───────┘  └────────────┬─────────────┘  │
│         └───────────┬─────┴───────────┬────────────┘                │
│                     ▼                 ▼                             │
│   ┌────────────────────────────────────────────────────────┐      │
│   │ API Gateway: REST + gRPC + mTLS, deny-by-default       │      │
│   └────────────────────────────────────────────────────────┘      │
│   ┌────────────────────────────────────────────────────────┐      │
│   │ Event Bus: Postgres outbox → NATS (S5)                 │      │
│   │ Storage: PostgreSQL + S3/MinIO                         │      │
│   └────────────────────────────────────────────────────────┘      │
│   ┌────────────────────────────────────────────────────────┐      │
│   │ Watchdog (S6): три линии (1 / 2a / 2b / 3)            │      │
│   └────────────────────────────────────────────────────────┘      │
└─────────────────────────────┬──────────────────────────────────────┘
                              │ HTTPS + mTLS
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   ┌──────────┐         ┌──────────┐         ┌──────────┐
   │ GUI(Tauri)│         │ GUI(веб) │         │ Агенты   │
   │ reqwest+ │         │          │         │ (mTLS)   │
   │ cert+DPAPI│         │          │         │          │
   └─────┬────┘         └──────────┘         └──────────┘
         ▼
   ┌──────────┐
   │ TUI (SSH)│ аварийный доступ (не mTLS-fallback)
   └──────────┘

   ┌────────────────────────────────────────────────┐
   │ Agent Connector (stml-agent-bridge, Python)    │
   │  - Python-клиент к core/ipc.py (pickle)        │
   │  - внутренний JSON-RPC на 127.0.0.1:port       │
   │    (динамический порт + lock-файл PID + hash)  │
   │  - fallback через *.jsonl                      │
   │  - SQLite-буфер, retry, offline mode           │
   └────────────────────────────────────────────────┘
```

### 1.1. Компоненты и уровни доверия

| Уровень | Компоненты | Права | Подпись |
|---|---|---|---|
| **T0 (ядро)** | API Gateway, Trust Service | Максимальные | Human-подпись (уровень C) |
| **T1 (критичные)** | Fleet Manager, Learning Pipeline, **Agent Connector (Python)** | Управление, обучение, чтение агента | Human-подпись + авто-ревьюер |
| **T2 (детекторы)** | pe_rf, elf_rf, behavior_if, script_tfidf, memory_scan, net_model | Только свои данные | Авто-ревьюер + подпись |
| **T3 (внешние)** | Локальные ИИ оператора (Ollama, своя) | Только предложения | Без подписи (советник) |

> T3 — **уровень доверия**, не слой A/B/C. Слои и уровни — разные оси.

### 1.2. Agent Connector — детализация

**Что это:** процесс-адаптер между текущим агентом и STML. Работает с существующим `core/ipc.py`, не меняя ядро агента.

### 1.2a. Верификация источников по коду (S0.0a, выполнено)

| Источник | Статус | Подтверждение |
|---|---|---|
| `core/ipc.py` — 10 RPC | ✅ | `ipc.py:324–333` |
| Ролевая авторизация | ✅ | viewer/operator/admin на каждом `register` |
| Transport: pickle | ✅ | `multiprocessing.connection` + `pickle.loads` (`ipc.py:16,22,159`) |
| authkey | ✅ | `Listener(address, authkey=...)`; источник — `AIDF_AUTHKEY` (hex) env, иначе `os.urandom(32)` (`aidf_service.py:139-140`) |
| Лимит 1 MiB | ✅ | `MAX_MESSAGE = 1 << 20` (`ipc.py:27`) |
| Файлы `*.jsonl` | ✅ | `audit/chain.jsonl` (`daemon.py:100`), `quarantine.jsonl` (`:115`), `spool/events.jsonl` (`:118`) |
| `schemas/v3/` | ✅ | каталог JSON Schema |
| `aidfctl.py` | ✅ | `scripts/aidfctl.py` |
| `MODELS_TRAIN_ON_DEVICE=False` | ✅ | эталон `core/policy.py`, зеркало `rust/src/policy.rs` |

**Разрыв контракта подтверждён:** `get_inventory`, `get_policy_state`, `suspend`, `resume` — не зарегистрированы. Fallback через файлы — обязателен.

**Семантика RPC (исправлена по коду):**

| Метод | Роль | Семантика | Обратим? |
|---|---|---|---|
| `ping` | viewer+ | проверка связи | — |
| `health` | viewer+ | состояние агента (`daemon.health()`) | — |
| `stats` | viewer+ | статистика (`daemon.stats()`) | — |
| `self_test` | operator+ | самопроверка (`run_self_test`) | — |
| `immutable_check` | operator+ | `verify_immutable()` — fingerprint immutable-политики | — |
| `confirmations` | viewer+ | список ожидающих подтверждений | — |
| `confirm` | operator+ | подтвердить действие (approved/rejected) | — |
| `quarantine` | operator+ | изолировать **объект/файл** по `path` | да (снятие) |
| `kill_switch` | admin | отключить **правило** по `rule_id` | да (снятие правила) |
| `shutdown` | admin | завершить агент | нет |

> **`suspend`/`resume` не эмулируются:** `shutdown` — глобальная остановка агента; `kill_switch` — kill правила; `quarantine` — изоляция объекта. **`suspend` = серверный флаг «STML перестаёт слать команды агенту» (в БД), `resume` = снятие флага.** Обратимо, без RPC.

**Как читает агента:**
- **Основной путь (ADR D15):** Python-клиент к `core/ipc.py` (pickle) + внутренний JSON-RPC на `127.0.0.1:port`. Коннектор работает с JSON; pickle локализован и наружу не выходит.
  - Порт динамический (0) + lock-файл с PID + hash бинарника; если порт занят — `degraded`, не тихий fallback.
  - ACL на pipe/socket — S0.1b.
- **Fallback (обязателен):** read-only через `*.jsonl` (`audit/chain.jsonl`, `quarantine.jsonl`, `spool/events.jsonl`). Offset в SQLite, partial line, детекция ротации (inode/размер), без дублей (по `report_id`).
- **Polling** (10 с) + подписка (если агент поддержит push).
- **Таймауты:** 2 с на RPC; при недоступности — `degraded`, буфер, retry с backoff.

**Что если агент недоступен:** SQLite-буфер (P0 не теряется), retry 1→2→4→…→5 мин, offline mode, алерт в GUI.

**Что если STML/коннектор kill:** буфер досылается после восстановления; идемпотентность по `report_id`; SQLite integrity_check при старте; лимит буфера 7 дней / 1 ГБ, P0 вытесняет P1–P3, P0 не вытесняется.

**Как обновляется:** отдельный подписанный пакет (Ed25519), отдельный ключ коннектора; канал stable/canary; проверка совместимости `schemas/v3 → stml/v0`; при несовместимости — `degraded` + алерт; `key_id` в пакете + доверенные `key_id`.

**Технология:** Python (T1-адаптер), Rust избыточен.

**Владелец:** T1, human-подпись + авто-ревьюер. Имя — в `docs/owners.md` (до S0.1a).

**Контракт коннектора:** `docs/stml-agent-bridge.md` (включая JSON-RPC-схему).

### 1.3. Mini-threat model Agent Connector (STRIDE)

Артефакт: `docs/threat-model-connector.md`.

| STRIDE | Угроза | Митигация |
|---|---|---|
| Spoofing | поддельный heartbeat/inventory | ACL pipe/socket; сверка PID+hash; authkey handshake |
| Tampering | инъекция в данные | read-only ACL; integrity_check; подпись буфера |
| Repudiation | отрицание отправки | append-only локальный audit (Ed25519-цепочка) |
| Information disclosure | утечка raw-логов | нормализация по `stml/v0`, PII-фильтр, запрет raw |
| DoS | переполнение буфера | лимит 7 дней/1 ГБ, ротация, backpressure |
| Elevation | лишние права | capability-based, отдельный пользователь, seccomp/AppArmor |
| Replay | повтор отчёта | nonce + timestamp + подпись + skew limit |
| Format drift | смена схемы | версионирование, `degraded` + алерт |
| Pickle-RCE | выполнение кода | доверенный endpoint, лимит 1 MiB, валидация типов, **тест #6.5** |

### 1.4. Остаточные риски коннектора (приняты)

| Риск | Принят | Тест |
|---|---|---|
| Компрометация ОС до установки | да, не покрыт | — |
| Злоумышленник с правами админа | да, не покрыт | — |
| Supply chain ключа коннектора | частично | отзыв в сессии (S2) |
| Format drift | да | схема версионируется + degraded-алерт |
| Утечка authkey из памяти | частично, не покрыт | ротация/отдельный пользователь |
| Rust-порт ломает совместимость | снято (Rust вне области S0–S3) | — |
| Битый pickle → RCE | да | тест #6.5 |

---

## 2. Этапы (полный объём, порядок под проект)

### 2.0. Матрица совместимости схем

| Схема | Владелец | Поддержка | При несовместимости |
|---|---|---|---|
| `schemas/v3` (агент) | владелец агента | пока агент пишет | коннектор адаптирует → `stml/v0` |
| pickle-схема `core/ipc.py` | владелец агента | пока используется | Python-клиент + JSON-RPC (ADR D15) |
| JSON-RPC (внутренний) | владелец коннектора | вместе с `stml/v0` | `degraded` + алерт |
| `stml/v0` | security engineer + владелец коннектора | ≥2 минорных STML | `degraded` + алерт, P0 буферизуется |
| `stml/v1` | security engineer + владелец коннектора | ≥2 минорных после v1 | capability negotiation |

**Правила:** breaking change — новая мажорная + ADR + human-подпись; сервер поддерживает N и N−1 (для `stml/v0` N−1 не существует); коннектор объявляет capabilities; CI-тесты «старый↔новый».

---

### S0 — Фундамент: контракты + Agent Connector

**Слои:** A = S0.0 → S0.1a → S0.1b; B = спайки `rust-pkcs11`/Tauri mTLS, property-based; C = владельцы, соглашение с владельцем агента.

**Предусловие S0.0a:**
- **Rust-порт — вне области STML на S0–S3** (в пилоте только Python-агент). Решение владельца зафиксировано.
- **Семантика RPC зафиксирована по коду** (§1.2a): `kill_switch`=rule, `shutdown`=агент, `quarantine`=объект, `immutable_check`=fingerprint.

#### S0.0 — Discovery

**S0.0a — Быстрый скан (выполнено):** карта источников, источник authkey, семантика RPC, arm64 (Windows on ARM — отметить «не проверено, CI-матрица»). Артефакт: `docs/stml-source-inventory-quick.md`.

**S0.0b — Детальная карта:** поля/форматы/частота для работающего; схема `stml/v0` (enrolment, heartbeat, inventory, policy, report, command, ack, error); маппинг 5 ключевых RPC (enrolment, heartbeat, inventory, report, ack); механика `*.jsonl`. Артефакт: `docs/stml-source-inventory.md`.

**S0.0c — Гейт (решение):**
- **ADR D15 (pickle→JSON)**: Python-клиент + внутренний JSON-RPC; порт динамический + lock-файл PID + hash; при занятости — `degraded`.
- **ADR D14 (multi-tenant)** — черновик.
- **Решение по разрыву контракта:** `get_inventory`/`get_policy_state` — fallback через файлы; `suspend`/`resume` — серверный флаг.
- **Соглашение с владельцем агента** о breaking changes ≥2 недели.
- Артефакт: `docs/s0-decision.md`.

**Стоп-кран S0.0:** нет доступа/`core/ipc.py` не работает и файлов нет → эскалация владельцу проекта; владелец агента не назначен → S0.0c не закрывается. **Владелец решения:** security engineer. **Эскалация:** владелец проекта ≤72 ч.

#### S0.1a — Коннектор-минимум → VS1

**Слой A:** Python-клиент + JSON-RPC + fallback + SQLite-буфер + тесты #1–#6 + #6.5.

| # | Тест | Риск |
|---|---|---|
| 1 | enrolment | spoofing (one-time token + Ed25519) |
| 2 | heartbeat | DoS (приоритеты + backoff) |
| 3 | inventory (fallback) | tampering (read-only ACL + integrity) |
| 4 | policy | инъекция (валидация + allowlist) |
| 5 | report P0 | потеря (spool + ACK) |
| 6 | replay | nonce + timestamp + skew |
| 6.5 | битый pickle | pickle-RCE (валидация типов, 1 MiB, доверенный endpoint) |

**Gate S0.1a (VS1):** live-агент: heartbeat ≤10 с, inventory ≤30 с; fallback работает; P0 не теряется при kill STML/коннектора/ОС; дубликатов 0.

#### S0.1b — Укрепление

**Слой A:** ACL pipe/socket; `key_id` + доверенные `key_id`; подпись пакета (ключ коннектора); threat model + остаточные риски (`human_acceptance`); **маппинг 5 read-only RPC: `ping`, `health`, `stats`, `self_test`, `immutable_check`** (не 5 ключевых; команды — S1/S3).

**Gate S0 (полный):** `stml/v0` заморожен; тесты 6+6.5; threat model согласованы; ключ коннектора создан, пакет подписан; ADR D14/D15; `tenant_id` в схеме; стенд (4 ВМ) развёрнут; ACL настроены; 5 read-only RPC маппятся.

**Стоп-краны:** threat model не согласован → S1 не стартует; ключ не создан → S0.1b не закрыт.

---

### S1 — Fleet Core + приём отчётов + GUI read-only

**Слой A:** реестр (enrolment → heartbeat/inventory → report ingest + audit chain) + GUI read-only (Dashboard/Fleet/Agents) + TUI (health, kill-switch) + **TUI kill-switch ≤5 мин**.
**Слой B:** policy CRUD + dry-run + diff + rollout canary + halt/rollback.
**Слой C:** владельцы зафиксированы.

> **⚠️ УТОЧНЕНИЕ (kill-switch S1 = TUI; GUI = S3):** S1 — TUI (аварийный, SSH, Admin); S3 — GUI (с подтверждением, RBAC). Разделено.

> **⚠️ УТОЧНЕНИЕ (policy CRUD B vs gate «подпись»):** gate S1 проверяет **механизм подписи на тестовой policy (dry-run)**, а не наличие production-policy. Тестовая policy создаётся, подписывается ключом policy (S0.1b), проверяется на dry-run, аудит фиксирует.

**p95 heartbeat — операционализация (v1.2.1 P-01):**
- Измеряем: timestamp в payload → запись в `agents.last_seen` (БД). Не GUI-отображение.
- Baseline на 10 агентах до оптимизации — `docs/s1-baseline.md`.
- Профиль нагрузки — `docs/s1-load-profile.md` (размер inventory, частота отчётов, доля P0-всплесков).
- Критерий провала: p95 >2 с на baseline/100 синтетических — стоп-кран S1 (оптимизация/инцидент).

**P0 потерь 0 — операционализация (v1.2.1 P-02):**
- «Потеря P0» = отчёт priority=P0 есть в spool/буфере, но не появился в `reports` после восстановления.
- «Дубликат» = два `reports` с одним `report_id`.
- **`report_id` генерирует коннектор** (persistent в SQLite-буфере). Зафиксировать в S0.0b.

**Gate S1:** 1+ агент online, p95 ≤2 с; нагрузочный 100 синтетических; TUI kill-switch ≤5 мин; P0 потерь 0; подпись policy на тестовой policy (dry-run); canary rollback (или ADR «отложено»); deny-by-default; GUI read-only.

**Стоп-краны S1:** p95 >2 с на 500 — инцидент S1 (эскалация, проверка транспорта). **Владелец:** security engineer. **Эскалация:** владелец проекта ≤72 ч.

---

### S2 — Trust Service (prod)

**Слой A:** prod HSM + quorum + миграция ключей S0→prod (overlap, `key_id`) + подпись/проверка + тесты #7–#10 + human-approval + audit log + отзыв ≤24 ч + key ceremony.
**Слой B:** ротация, backup/restore, immutable guards, threat model Trust Service.
**Слой C:** пилот стабилен (S1 ≥99,5%, S11=0, S12 ≥99,9%, S13=100%) — условие выхода из пилота, не блокер гейта.

> **⚠️ УТОЧНЕНИЕ (quorum, v1.2.1 P-03):** 2 из 3 (рекомендуется) или 2 из 2 (с риском); выбор PM+security engineer до S2, фиксируется в `docs/key-ceremony.md`. При недоступности quorum — раскатка блокируется, алерт, эскалация ≤1 ч. **Исключение: аварийный KS-4 не требует quorum** (это отключение, не подпись). Key ceremony — роли/свидетели в `docs/key-ceremony.md`.

> **⚠️ УТОЧНЕНИЕ (S2 C не блокирует гейт):** S2-гейт (A) может закрыться без C, но **масштабирование >100 запрещено до C**.

**Gate S2:** prod HSM + quorum; миграция с overlap; тесты #7–#10; отзыв ≤24 ч; ротация; audit verify 100%; restore RTO ≤1 ч; immutable guards в CI; key ceremony; threat model; SoD (Admin≠approve, Approver≠kill-switch).

**Правило «S2 задерживается»:** S1 с SoftHSM — только пилот (≤100, ≤1 тенант), письменное принятие риска, 8 недель; >100 — обязателен S2.

**Стоп-кран S2:** YubiHSM недоступен → fallback SoftHSM (dev), пилот с принятием риска, не масштабировать >100; миграция провалилась → откат, эскалация.

---

### S3 — Терминал GUI (полный)

**Слой A:** Tauri mTLS (`reqwest` + client cert + DPAPI) + экраны + dry-run/kill-switch/human-approval + RBAC/SoD + GUI не хранит секретов.
**Слой B:** TUI, план обучения, S18/S19, WebSocket для 1000+.
**Слой C:** DPIA — перенесена в финал (не блокирует S3).

> **⚠️ УТОЧНЕНИЕ (спайк mTLS — блокирующий, v1.2.1 P-04):** спайк Tauri mTLS в S0.1b — результат блокирующий для S3. Если спайк провален → S3 перепланируется (браузерный GUI + reverse-proxy mTLS, или TUI + mTLS-клиент), а не «+20–30% времени». Критерий mTLS: client cert из OS-хранилища, ротация, отзыв (CRL/OCSP); сертификат не в файле/коде.

> **⚠️ УТОЧНЕНИЕ (тренинг A/B):** Gate S3 (A) — технический. Тренинг (B) не блокирует гейт, но **допуск к production GUI — только после тренинга** (чек-лист `docs/operator-training.md`).

> **⚠️ УТОЧНЕНИЕ (GUI kill-switch):** GUI kill-switch — с подтверждением, RBAC, Admin; Approver — не может. TUI — аварийный.

**Gate S3:** оператор видит флот, dry-run, раскатка, откат, approve из GUI; модули вкл/выкл; GUI не хранит секретов; TUI; RBAC+SoD; GUI kill-switch; тренинг — допуск отдельно.

---

### S4 — Learning Pipeline

> **Адаптация v1.3:** DPIA **не блокирует** S4.1. Юрист привлекается в финале (перед production/масштабированием). До этого — opt-in + анонимизация по ADR D12 (телеметрия наружу). При первом реальном сборе телеметрии и перед масштабированием — DPIA обязательна. Риск принят владельцем.

**Слой A:** приём opt-in телеметрии (PII-фильтр, retention) → курирование/разметка (`case_id`, SLA разметки, ≥500 кейсов/итерацию) → модели (песочница, replay-буфер, офлайн-retrain) → регрессия (holdout отдельно) → подпись → staged rollout → **dual-slot откат ≤15 мин**.
**Слой B:** внешние модели-советники (без подписи).

**Baseline (v1.2.1 P-14):** `docs/s4-baseline.md` + скрипт + датасет + seed — иначе не зафиксирован; ревью security engineer + PM; «покрытие 100%» операционально.

**Политика no-regression:** TPR@FPR и FP-бюджет не хуже baseline; holdout не из API; 3 итерации провала — red-team + эскалация; авто-деплой запрещён.

**Gate S4:** телеметрия анонимизирована; оператор подтверждает выборку; модель обучается/регрессирует/подписывается; внешняя модель — советник; метрики с baseline в GUI; `MODELS_TRAIN_ON_DEVICE=False` (CI); no-regression; dual-slot ≤15 мин.

---

### S5 — Масштаб транспорта

**Триггер:** 800 агентов при работающем S1 → подготовка S5; **инцидент S1** (p95 >2 с на 500) — эскалация, не триггер S5.

> **⚠️ УТОЧНЕНИЕ (NATS vs Kafka, v1.2.1 P-08):** Kafka — если уже есть кластер / нужна партиционная модель; NATS — если нет. Решение DevOps+PM до старта S5, ADR D16. **Postgres outbox — не fallback при >1k**; реальный fallback — остановка масштабирования + алерт.

**Gate S5:** P0 не теряется (1k); дубликаты 0; offline 7 дней; kill-switch ≤5 мин на 1k; replay-защита.

---

### S6 — Ops и наблюдаемость

**Слой A:** SLO S1–S19 + error budget; watchdog (три линии: 1 внутренний / 2a Prometheus / 2b SIEM / 3 облачный uptime или локальный пробер); `windows_exporter`; матрица «метрика→алерт→действие»; OTel `trace_id`; backup/restore; runbook; pen-test STML.

> **⚠️ УТОЧНЕНИЕ (watchdog, v1.2.1 P-12):** линия 2a — **обязательно отдельный хост** (не «желательно»). Air-gapped ручной чек-лист — часть gate S6.

> **⚠️ УТОЧНЕНИЕ (pen-test CVSS):** критичные/высокие (CVSS ≥7.0) — исправлены до приёмки; средние — план SLA ≤30 дней; низкие — бэклог.

**Gate S6:** SLO в целях; watchdog ≤60 с; матрица зафиксирована; трейс полный; backup восстановлен; runbook; pen-test (CVSS критерий).

---

### S7 — Развёртывание

**Слой A:** Compose ≤30 мин; K8s HA + rolling; air-gapped (anti-rollback + журнал USB + dual-slot + план B); DR-тест.

> **⚠️ УТОЧНЕНИЕ (DR-тест, v1.2.1 P-13):** DR-тест соответствует целевому стенду: Compose — backup-restore (RTO ≤1 ч); K8s — полный DR (RTO ≤4 ч) при первом развёртывании. **HSM ceremony не входит в RTO ≤4 ч** (ceremony отдельно, SLA ≤24 ч).

**Gate S7:** Compose; K8s; air-gapped; DR-тест на целевом стенде; `docs/deploy.md`.

---

### S8 — Сосуществование и multi-tenant

**Слой A:** топ-3 EDR; режим `compat`; матрица ОС; multi-tenant (финализация ADR D14); SIEM-экспорт.

> **⚠️ УТОЧНЕНИЕ (multi-tenant решение до S8, v1.2.1 P-07):** «нужен/не нужен» решается в S1 (первый клиент / регуляторное требование). «>10 тенантов» — про RLS-производительность, не про необходимость; измерить в S8. Если «не нужен» — S8 закрывается с обоснованием, `tenant_id` остаётся.

**Gate S8:** топ-3 EDR пройдены; матрица в `docs/compat.md`; tenant-изоляция; SIEM; ADR D14 финализирован.

---

## 3. Вертикальные срезы, kill-switch, масштабирование

### 3.1. Вертикальные срезы (VS1–VS10)

VS1 (S0.1a, live-агент) → VS2 (S1, GUI read-only) → VS3 (S1B, dry-run) → VS4 (S2, human-approval) → VS5 (S3, раскатка/откат/GUI kill-switch) → VS6 (S4, обучение) → VS7 (S5, масштаб) → VS8 (S6, SLO/трейсы) → VS9 (S7, air-gapped) → VS10 (S8, multi-tenant/SIEM).

### 3.2. Матрица масштабирования

| Масштаб | Транспорт | Триггер | Тенанты | Модели | GUI |
|---|---|---|---|---|---|
| ≤100 | Postgres outbox | MVP | 1 | ≤100 МБ | ≤1000 строк |
| 100–1000 | + партиционирование + батчинг | p95 >2 с / очереди >10k | ≤10 (RLS) | ≤500 МБ (S3) | виртуализация |
| >1000 | NATS JetStream | 1000+ / шторм | >10 | >500 МБ (шардирование) | серверная пагинация |
| >10000 | Kafka | интеграция / 10k+ | шардирование | — | — |

### 3.3. Семантика kill-switch (KS-1..KS-5)

Runbook: `docs/runbook-kill-switch.md`.

| Режим | Что отключается | Когда |
|---|---|---|
| KS-1 Halt rollout | текущая раскатка | ошибка раскатки |
| KS-2 Rollback policy | активная policy → предыдущая | policy ломает агентов |
| KS-3 Rollback model | активная модель → предыдущая (dual-slot) | регресс модели |
| KS-4 Freeze fleet | все команды | инцидент STML |
| KS-5 Isolate agent | конкретный агент | компрометация агента |

**S4:** ≤5 мин KS-1..KS-3; ≤1 мин KS-5. **TUI kill-switch (S1), GUI kill-switch (S3).** KS-4 — без quorum.

---

## 4. Роли, RACI, error budget, метрики

### 4.1. Роли

| Роль | Ответственность | Назначение |
|---|---|---|
| Владелец проекта | эскалация, финальные решения | до S0.0a |
| Владелец агента | уведомление о breaking changes v9.1 | до S0.0c |
| Владелец Agent Connector | коннектор, JSON-RPC, `stml/v0` | до S0.1a |
| PM | внешний путь, приёмка | до S0.0a |
| Security engineer | threat model, ACL, red-team | S0+ |
| ML-инженер | обучение, регрессия, baseline | S4 |
| Оператор | GUI, инциденты, on-call | S1+ |
| DevOps | Compose/K8s, backup, watchdog | S7 |
| Юрист/DPO | DPIA (финал) | перед production |

**Назначение владельцев (v1.2.1 P-06):** владелец проекта — совет директоров/инвесторы; владелец агента — владельцем проекта; владелец коннектора — PM + security engineer; PM — владельцем проекта. Фиксируется письменно в `docs/owners.md`.

### 4.2. RACI (гейты, с A')

| Гейт | R | A | A' | C |
|---|---|---|---|---|
| S0.0 | владелец коннектора | security engineer | PM | PM |
| S0.1a | коннектор + агент | security engineer | PM | — |
| S0.1b | коннектор + security engineer | security engineer + PM | PM | юрист/DPO |
| S1 | DevOps + агент | PM | security engineer | security engineer |
| S2 | DevOps + security engineer | PM | security engineer | юрист |
| S3 | агент + оператор | PM | security engineer | security engineer |
| S4 | ML-инженер | PM + ML-инженер | security engineer | security engineer |
| S5 | DevOps | PM | security engineer | security engineer |
| S6 | DevOps | PM | security engineer | security engineer |
| S7 | DevOps | PM | security engineer | security engineer |
| S8 | DevOps + агент | PM + security engineer | юрист | юрист |

Эскалация: A/A' 48 ч → владелец проекта ≤72 ч.

### 4.3. Error budget

| SLO | Цель | При превышении |
|---|---|---|
| S1 доступность | 99,5% → 99,9% | freeze фич |
| S5 обновления | ≥99,9% | freeze, dual-slot |
| S11 P0 потери | 0 | critical, runbook |
| S12 rollout | ≥99,9% | freeze, canary |
| S13 audit | 100% | critical |
| S15 key compromise | ≤24 ч | critical, ротация |

### 4.4. Метрики S1–S19

| # | Метрика | Цель |
|---|---|---|
| S1 | доступность | 99,5% → 99,9% |
| S2 | heartbeat→GUI p95 | ≤2 с |
| S3 | canary→100% | ≤7 дней |
| S4 | kill-switch ACK | ≤5 мин (KS-1..3), ≤1 мин (KS-5) |
| S5 | обновления STML | ≥99,9% / откат 100% |
| S6 | тихий отказ | 100% за ≤60 с |
| S7 | API по умолчанию | 0% (кроме health/enrolment) |
| S8 | кейс→подписанная модель | ≤30 дней |
| S9 | recall ревьюера | ≥95% (выборка ≥100) |
| S10 | драйвер human-review | 100% (через STML) |
| S11 | report durability | 0 потерь P0 |
| S12 | rollout success | ≥99,9% |
| S13 | audit verify | 100% |
| S14 | backup RTO/RPO | ≤1 ч / ≤15 мин |
| S15 | key recovery | ≤24 ч |
| S16 | откат модели | ≤15 мин (dual-slot) |
| S17 | стоимость | «по факту», без фикс. бюджета |
| S18 | доля отменённых действий | ≤15% (S3) → ≤5% (S6); мин. 50 действий/нед |
| S19 | доля инцидентов от оператора | ≤5% → ≤1%; мин. 50/нед |

> **S18/S19 (v1.2.1 P-15):** при провале — пересмотр тренинга, приостановка допуска, аудит действий; «недостаточно данных» при <50/нед.

### 4.5. Стоимость

Не рассчитывается (по факту). Порядок урезания при нехватке ресурсов: S4 → S3 (read-only) → S1 (health/enrolment). **S0, S2, S6 — не режутся.**

---

## 5. Риск-реестр (сводный)

| Риск | Митигация |
|---|---|
| pickle-схема меняется | версионирование + CI |
| authkey утекает | ротация, отдельный пользователь |
| ручной маппинг 10 RPC | Pydantic + property-based |
| Tauri mTLS не нативно | `reqwest` + cert + DPAPI; спайк-блокер |
| SQLite spool не масштабируется | NATS при >1k |
| разрыв контракта | fallback через файлы |
| `suspend`/`resume` через kill_switch | серверный флаг (не эмуляция) |
| JSON-RPC порт занят | динамический порт + lock PID + hash |
| формат логов меняется | версионирование + degraded-алерт |
| HSM несовместим с Rust | `rust-pkcs11`/`yubihsm-pkcs11` |
| quorum на одном HSM | ≥2 HSM |
| NATS нестабилен | Kafka (если критерий) / остановка масштабирования |
| шторм heartbeat | приоритеты + батчинг + jitter |
| раскатка ломает агентов | canary + halt + откат + подпись |
| human-approval узкое место | SLA 48 ч, A' |
| отравление обучения | курирование, replay, holdout |
| внешняя модель утечка | localhost, opt-in |
| prompt-injection | нет авторитета, гейт |
| потеря P0 | отдельная дисковая очередь |
| дубликаты | `report_id` (генерирует коннектор) |
| DDoS | rate limit, backpressure |
| компрометация STML | offline root, quorum, mTLS, audit |
| tenant-изоляция | tenant_id + RLS |
| ошибка оператора | тренинг, dry-run, S18/S19 |
| DPIA задерживает S4 | **снято: DPIA в финале** (риск принят) |
| `node-exporter` на Windows | `windows_exporter` |
| S5 триггер маскирует инцидент S1 | разделено |

---

## 6. Открытые решения владельца

| # | Вопрос | Статус |
|---|---|---|
| 1 | HSM | SoftHSM dev → YubiHSM+quorum prod |
| 2 | Event bus | outbox → NATS при >1k (ADR D16) |
| 3 | GUI | Tauri + TUI + опц. браузер |
| 4 | Обучение | встроенные → внешние-советники |
| 5 | Pull/push | pull + опц. push |
| 6 | Air-gapped | проектировать, строить S7 |
| 7 | Multi-tenant | single-tenant MVP, tenant_id S0, ADR D14 |
| 8 | Deploy | Compose → K8s |
| 9 | Внешние ИИ | советник, без подписи |
| 10 | DPIA | **в финале (юрист в конце)** |
| 11 | Что доступно в `core/ipc.py` | закрыто верификацией |
| 12 | Владелец коннектора | назначить до S0.1a |
| 13 | kill-switch семантика | KS-1..KS-5 |
| 14 | анонимизация | хеширование + удаление raw + k-anonymity |
| 15 | бюджет | **по факту, не фиксируется** |
| 16 | ADR D15 (pickle→JSON) | решить в S0.0c |
| 17 | suspend/resume | серверный флаг |
| 18 | windows exporter | `windows_exporter` |
| 19 | владелец проекта | назначить до S0.0a |
| 20 | слой B что отложить | спайки→S2, policy CRUD→S1.5, WebSocket→по факту |
| 21 | владелец агента | назначить до S0.0c |
| 22 | 5 read-only RPC | ping/health/stats/self_test/immutable_check |
| 23 | kill-switch S1 | TUI (S1) / GUI (S3) — интерпретация |
| 24 | тренинг S3 | B; допуск после тренинга |
| 25 | policy CRUD vs gate | механизм подписи на тестовой policy — интерпретация |
| 26 | S2 C | не блокирует гейт; >100 после C |
| 27 | S4 C→A | **снято: DPIA в финале** |
| 28 | S6 CVSS | ≥7.0 до приёмки |
| 29 | S7 DR | соответствует целевому стенду |
| 30 | §12.20 пилот 1–5 | по факту, без фикс. сроков |

---

## 7. Чек-лист готовности к production (слои + «Проверяет»)

### S0
- [ ] v1.3 в `docs/stml-roadmap.md`. **[C] PM**
- [ ] Владельцы назначены (`docs/owners.md`). **[C] PM**
- [ ] S0.0a: карта источников + authkey + семантика RPC + arm64. **[A] security engineer + PM**
- [ ] S0.0b: `stml/v0` + маппинг 5 RPC + механика `*.jsonl`. **[A] security engineer + коннектор**
- [ ] S0.0c: ADR D14/D15 + `docs/s0-decision.md` + соглашение с владельцем агента. **[A] security engineer + PM**
- [ ] S0.1a: коннектор-минимум + тесты #1–#6+#6.5; VS1. **[A] коннектор + security engineer**
- [ ] S0.1b: ACL + `key_id` + подпись + 5 read-only RPC + threat model. **[A] коннектор + security engineer**
- [ ] Property-based тест. **[B] коннектор**
- [ ] Стенд 4 ВМ. **[C] DevOps**
- [ ] Rust-порт вне области (решение). **[C] владелец + security engineer**

### S1
- [ ] S1-функциональный (1+ агент, p95 ≤2 с) + нагрузочный (100 синтетических). **[A] PM + DevOps**
- [ ] TUI kill-switch ≤5 мин. **[A] security engineer + оператор**
- [ ] Подпись policy на тестовой policy (dry-run). **[A] security engineer**
- [ ] P0 потерь 0; GUI read-only; deny-by-default; матрица масштабирования; ADR D14. **[A] PM + security engineer**
- [ ] Policy CRUD + rollout. **[B] коннектор + оператор**

### S2
- [ ] Prod HSM + quorum; миграция с overlap. **[A] PM + security engineer**
- [ ] Тесты #7–#10; отзыв ≤24 ч; restore RTO ≤1 ч; key ceremony; SoD. **[A] security engineer**
- [ ] Ротация, immutable guards. **[B] DevOps + security engineer**
- [ ] Стабильность пилота (C). **[C] PM**

### S3
- [ ] Tauri mTLS (спайк-блокер); RBAC+SoD; GUI kill-switch; dry-run; human-approval; GUI без секретов. **[A] security engineer + оператор**
- [ ] TUI; тренинг (допуск после); S18/S19; WebSocket. **[B] оператор**

### S4
- [ ] Телеметрия анонимизирована; `case_id`; SLA разметки. **[A] ML-инженер**
- [ ] Модель обучается/регрессирует/подписывается; no-regression; dual-slot ≤15 мин. **[A] ML-инженер + security engineer**
- [ ] Baseline воспроизводим (скрипт+датасет+seed), ревью. **[B] ML-инженер**
- [ ] DPIA — **в финале** (перед production). **[C] юрист/DPO**

### S5
- [ ] Триггер 800 агентов; инцидент S1 разделён. **[C] PM + DevOps**
- [ ] P0 не теряется; дубликаты 0; offline 7 дней; kill-switch ≤5 мин на 1k; replay. **[A] DevOps + security engineer**
- [ ] Kafka (если критерий). **[B] DevOps**

### S6
- [ ] SLO + error budget; три линии watchdog (2a отдельный хост); `windows_exporter`; OTel; runbook; pen-test (CVSS). **[A] DevOps + security engineer**
- [ ] Независимость линий; on-call. **[B] DevOps + оператор**

### S7
- [ ] Compose; K8s; air-gapped (anti-rollback + журнал USB + план B); DR-тест на целевом стенде. **[A] DevOps + PM**

### S8
- [ ] Топ-3 EDR; матрица ОС; tenant-изоляция; SIEM; ADR D14. **[A] DevOps + security engineer**

---

## 8. Критический путь, MVP, MVP-lite

```
S0.0a (выполнено) → S0.0b → S0.0c → S0.1a (VS1) → S0.1b
                                        │
                                        └→ S1 → S2 → S3 → S4 → S5 → S6 → S7 → S8
```

**MVP:** S0 + S1 + S2 + S3. **MVP-lite:** S0 + S1 (пилот SoftHSM ≤100) + S3 read-only, принятие риска.

**Критерии выхода из MVP-lite:** S2 завершён + миграция; пилот стабилен (S1 ≥99,5%, S11=0, S12 ≥99,9%, S13=100%).

---

## 9. Комментарии (заметки)

1. S0.0a выполнено — `core/ipc.py` верифицирован.
2. pickle → JSON: ADR D15; JSON-RPC версионируется, владелец — коннектор.
3. Разрыв контракта: fallback через файлы; `suspend`/`resume` — серверный флаг.
4. Коннектор — Python; Rust — GUI/сервер.
5. Tauri mTLS — спайк-блокер, не «+20–30%».
6. HSM — quorum ≥2; `rust-pkcs11`/`yubihsm-pkcs11`.
7. Тесты #7–#10 — S2.
8. Baseline S4.0a — с методикой.
9. DPIA — финал (риск принят).
10. Бюджет/сроки — по факту.
11. Приоритет: v1.3 в `docs/stml-roadmap.md`.
12. Три линии watchdog; `windows_exporter`.
13. `report_id` генерирует коннектор.
14. S1-гейт: функциональный/нагрузочный; TUI kill-switch S1, GUI S3.
15. S5: триггер 800 vs инцидент S1.
16. S2 C не блокирует гейт; >100 после C.
17. Anti-rollback USB + журнал.
18. S9 формула; S10 область; S18/S19 мин. объём.
19. SoD; SLA информирования; RACI S0 A'=PM.
20. `aidfctl.py` — если дубль, убрать; спайки S0.1b — 2.
21. DPIA в финале — единственное отступление от v1.2 (решение владельца).

---

## 10. Что НЕ входит в STML

macOS/мобильные; коммерция/биллинг; runtime-контейнеры; сам агент (v9.1); драйвер (уровень C); `suspend`/`resume` агента (доработка агента, в STML — серверный флаг); пауза агента через `kill_switch` (не эмулируется).

---

## 11. Первые шаги (по факту)

1. Записать v1.3 (выполнено этим документом).
2. Назначить владельцев — `docs/owners.md` (имена).
3. Переименовать ADR: D14 (multi-tenant), D15 (транспорт коннектора), D16 (event bus) — `docs/adr.md`.
4. S0.0b: схема `stml/v0` + маппинг 5 RPC + механика `*.jsonl`.
5. S0.0c: ADR D14/D15, соглашение с владельцем агента.
6. S0.1a: коннектор-минимум → VS1.

---

## 12. Приложения (сводно)

### 12.1. Включение API
health/enrolment (S1) → policy/package (S2) → command/kill-switch (S3) → telemetry/learning (S4) → push (S5). Владелец Admin, подтверждение Approver, откат фича-флаг + KS-4, аудит.

### 12.2. Матрица ОС коннектора
Windows 10/11/Server 2019/2022; Ubuntu 22.04/24.04; Debian 12; RHEL 9; Fedora 40+; arm64 — проверить явно (CI). RHEL 8 — degraded (fallback).

### 12.3. Миграция ключей S0→S2
S0.1b (SoftHSM) → S2 (prod HSM quorum) → overlap (`key_id`) → отзыв старых → откат при провале.

### 12.4. «Агент сломал коннектор»
Детекция (проверка схемы при старте) → `degraded` + алерт → fallback/откат → эскалация владельцу коннектора + агента.

### 12.5. SLA информирования
Внутреннее ≤4 ч (critical); клиенты ≤24 ч (critical) / ≤72 ч (high); пост-мортем ≤7 дней.

### 12.6. RBAC (одна матрица)

| Роль | Fleet | Policies | Rollout | Trust | Kill-switch |
|---|---|---|---|---|---|
| Viewer | R | R | R | R | — |
| Operator | R | R/W dry-run | R/W canary | R | — |
| Admin | R | R/W | R/W | R | R/W |
| Approver | R | R | R | R/W approve | — |
| Auditor | R | R | R | R audit | — |

**SoD:** Admin ≠ approve; Approver ≠ kill-switch; смена роли — два человека.

### 12.7. Стенд
4 ВМ: агент текущий / агент предыдущий / без агента / другая ОС. Полная матрица ОС — CI.

### 12.8. Watchdog (три линии)
1 внутренний; 2a Prometheus (**отдельный хост**); 2b SIEM; 3 облачный uptime / локальный пробер (air-gapped). Windows — `windows_exporter`. Air-gapped ручной чек-лист — оператор on-call.

### 12.9. Обновление STML (air-gapped)
Пакет → подпись → USB (журнал) → проверка (подпись, хеш, anti-rollback) → dual-slot → откат → план B (restore, RTO ≤1 ч обычный / ≤4 ч полный DR).

### 12.10. Offboarding
Отзыв сертификата ≤1 ч; ротация ключей ≤24 ч; аудит ≤24 ч; уведомление ≤24 ч.

### 12.13. Тестирование на реальных угрозах
≥400 образцов/класс; ≥3000 benign; red-team 20 сценариев/ОС; holdout отдельно от API.

### 12.14. DR-план
Backup/restore: RTO ≤1 ч / RPO ≤15 мин; полный DR (K8s): RTO ≤4 ч (ceremony отдельно ≤24 ч).

### 12.16. Матрица «функция → этап»
enrolment/heartbeat/inventory/report P0 — S0.1a; 5 read-only RPC — S0.1b; policy CRUD/rollout — S1B; TUI kill-switch — S1; GUI kill-switch — S3; human-approval — S2; learning — S4; NATS/Kafka — S5; watchdog — S6; air-gapped — S7; multi-tenant/SIEM — S8.

### 12.17. Dogfooding ≠ pen-test
Dogfooding S3+ (внутри); pen-test STML S6+ (red-team атакует STML), до приёмки.

### 12.18. Обучение ролей
Оператор (S3), ML-инженер (S4), security engineer (S0/S2), DevOps (S7).

### 12.19. Качество документации
Threat model — ревью security engineer + владелец коннектора (T1); внешний — опция (ADR «без внешнего ревью»). Достаточно = «что защищаем / от кого / что если не сработает».

### 12.20. План при отсутствии ресурсов
Без бюджета S1 → пилот 1–5 вручную (стенд S0, оператор security engineer, чек-лист `docs/manual-pilot-checklist.md`); выход по факту (бюджет/эскалация), без фикс. срока.

---

## 13. Глоссарий

STML; KS-1..KS-5; P0–P3; RLS; DPIA (в финале); CRL/OCSP; dual-slot; replay-буфер; MVP-lite; baseline; holdout; degraded; capability; pickle; authkey (`AIDF_AUTHKEY`); ADR D14 (multi-tenant); ADR D15 (транспорт коннектора); ADR D16 (event bus); PE v2; ECE; k-anonymity; `rust-pkcs11`/`yubihsm-pkcs11`; `windows_exporter`; SoD; владелец проекта/агента/коннектора; слой A/B/C; стоп-кран; TUI/GUI kill-switch; тестовая policy (dry-run); `immutable_check` (= `verify_immutable()`, fingerprint immutable-политики; в S0.1b маппится как read-only).

---

## 14. Схема данных

| Таблица | Поля | Retention | Шифрование |
|---|---|---|---|
| agents | id, tenant_id, machine_id, version, status, last_seen | пока активен | AES-GCM (PII) |
| policies | id, tenant_id, version, yaml, signature, created_at | 365 дней | — |
| reports | id, tenant_id, agent_id, type, priority, payload, ack_at | 30 дней (P0 180) | AES-GCM |
| models | id, tenant_id, name, version, hash, signature, metrics | активная + 2 | — |
| audit_log | id, tenant_id, actor, action, target, timestamp, signature | 180 дней | append-only |
| cases | id, tenant_id, report_id, label, holdout_flag | 365 дней | AES-GCM |
| keys_metadata | id, tenant_id, key_class (root/policy/model/driver/connector), version, created_at, revoked_at | активен + 365 | — |

---

## 15. История изменений

| # | Раздел | Изменение |
|---|---|---|
| 1 | глобально | v1.2 → v1.3: бюджет/сроки «по факту», без сумм и недель |
| 2 | S4 | DPIA выведена из критического пути (юрист в финале) |
| 3 | глобально | ADR: D14 multi-tenant, D15 транспорт коннектора, D16 event bus (D11/D12/D13 заняты) |
| 4 | §1.2a | семантика RPC исправлена по коду (kill_switch=rule, shutdown=агент, quarantine=объект, immutable_check=fingerprint) |
| 5 | §1.2a | источник authkey зафиксирован: `AIDF_AUTHKEY` env → `os.urandom(32)` |
| 6 | S0.0a | Rust-порт вне области S0–S3 |
| 7 | §4.1 | владельцы + «кто назначает» → `docs/owners.md` |
| 8–28 | S1/S2/S3/S4/S5/S6/S7/S8/§4/§12/§13 | 21 правка v1.2.1 (P0–P3): P-01…P-21 |

**v1.2.1 P-01…P-21 (сводно):** P-01 p95 операционализация; P-02 P0/`report_id`; P-03 quorum 2-of-3/2-of-2 + KS-4 без quorum; P-04 спайк mTLS блокирующий; P-05 стоп-краны владелец/эскалация; P-06 владельцы «кто назначает»; P-07 multi-tenant до S8; P-08 NATS vs Kafka критерий (ADR D16); P-09 `immutable_check` семантика; P-10 dry-run операционализация; P-11 пилот 1–5 пул/оператор; P-12 watchdog 2a отдельный хост + ручной чек-лист; P-13 DR K8s при первом развёртывании + HSM ceremony вне RTO; P-14 baseline воспроизводимость + ревью; P-15 S18/S19 при провале; P-16 `immutable_check` в глоссарий; P-17 архив v0.9→v1.0; P-18 принципы 20–22; P-19 #23/#25 интерпретация; P-20 S0.0b в днях 6–10; P-21 5 read-only RPC ≠ 5 ключевых.

---

**Готов к запуску S0.0b.** Блокеры: имена владельцев (`docs/owners.md`), переименование ADR, соглашение с владельцем агента (S0.0c).
