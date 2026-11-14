# STML — журнал принятых решений

> Каждое спорное решение: **принято**, **почему**, **альтернативы**. Обновляется
> по ходу этапов. В конце разработки — сводка для приёмки.

## S0.0b–S0.1a (фундамент и коннектор)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-01 | Нумерация ADR | **D14 multi-tenant, D15 транспорт коннектора, D16 event bus** | переиспользовать D11/D12/D13 | D11/D12/D13 уже заняты (упаковка, телеметрия, EDR) |
| D-02 | Транспорт коннектора | **Python-клиент к `core/ipc.py` + внутренний JSON-RPC** | HTTP-прослушиватель в агенте; Rust-коннектор | не менять ядро агента; pickle локализован |
| D-03 | Семантика `kill_switch` | **kill правила по `rule_id`** | считать «остановкой агента» | подтверждено кодом `ipc.py:292-301` |
| D-04 | `suspend`/`resume` | **серверный флаг** | эмулировать через `kill_switch`/`shutdown` | разная семантика; эмуляция необратима |
| D-05 | `report_id` | **генерирует коннектор** (persistent SQLite) | генерирует агент | идемпотентность при перезапуске |
| D-06 | Rust-порт в STML | **вне области S0–S3** | включить и проверять совместимость | в пилоте только Python-агент |
| D-07 | DPIA | **в финале**, не блокирует S4.1 | блокировать S4.1 | решение владельца; до финала — opt-in + анонимизация |
| D-08 | Буфер отчётов | **SQLite outbox** | JSONL-файл; in-memory | durability, приоритеты, idempotency |
| D-09 | Внутренний RPC | **line-delimited JSON-RPC, 1 MiB** | HTTP/JSON | проще, без зависимостей, локально |
| D-10 | Политика вытеснения | **P0 никогда не вытесняется** | FIFO по всем | P0 = инцидент, потеря недопустима |
| D-11 | VS1 транспорт | **ConsoleTransport** | сначала поднять сервер | VS1 = live-агент в консоли, сервер — S1 |
| D-12 | Владельцы | **заказчик + AI-агент под human-approval** | ждать найма | работаем по факту |
| D-13 | HTTP-эндпоинт отчётов | **`POST /v0/reports`** | gRPC | REST проще для S1 |
| D-14 | `signature` в `stml/v0` | **nullable до S0.1b** | обязательна сразу | подпись — S0.1b, не блокирует VS1 |
| D-15 | Строгость схемы | **extra ignored** (пока) | `extra="forbid"` | совместимость при эволюции; ужесточить в S0.1b |
| D-16 | Защита локального RPC | **loopback + auth_token + ACL lock-файла** | только ACL; без токена | второй слой против локальных пользователей |
| D-17 | Подпись пакета | **Ed25519 + `key_id` + манифест файлов** | подпись только бинарника | проверка целостности набора файлов |
| D-18 | Threat model коннектора | **принята делегированно** (AI под human-approval) | ждать human-подписи до S0.1b | не блокирует S0; финальная подпись — приёмка |
| D-19 | 5 read-only RPC | **прокси к агенту: ping/health/stats/self_test/immutable_check** | только connector-level status | соответствует S0.1b |

## S1 (Fleet Core)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-20 | Хранилище S1 | **SQLite MVP** (`Store` интерфейс) | PostgreSQL сразу | быстрый протокол и тесты; Postgres — S1.5 |
| D-21 | Сервер S1 | **Python stdlib reference** | Rust/axum сразу | проверка протокола/UX до порта; Rust — production gate |
| D-22 | Аутентификация агента | **Ed25519 подпись тела + одноразовый enrolment token** | mTLS сразу | mTLS/CA — S2 |
| D-23 | Dashboard | **read-only HTML, viewer token в браузере** | полноценный SPA | S1 = read-only |
| D-24 | TUI kill-switch | **CLI `isolate` с admin token** | ratatui-интерфейс | SSH-совместимо; ratatui — S3 |
| D-25 | Policy CRUD/rollout | **отложено (слой B)** | реализовать в S1 | gate S1 закрывается без B |
| D-26 | Audit traffic | **audit только смены статуса и P0** | audit каждого heartbeat/report | иначе цепочка растёт на 864k/сутки |
| D-27 | Ключ агента | **Ed25519, `<state>.key.pem`, генерируется один раз** | ключ в ОС-хранилище/TPM | S1.5; перенос в хранилище — S2 |
| D-28 | Isolated-режим | **heartbeat продолжается, reports буферизуются** | полностью отключать агент | KS-5: диагностика нужна |
| D-29 | Подпись reports | **тем же ключом агента, `X-STML-Signature`** | подпись каждого report | один конверт на батч |
| D-30 | Ключ policy | **отдельный Ed25519, `policy_pubkey` в конфиге сервера** | ключ агента | разные классы ключей |
| D-31 | Rollout | **детерминированно первые N% агентов, `old_version` для rollback** | случайная выборка | воспроизводимость |
| D-32 | Policy content | **JSON dict, канонизация sorted** | YAML | проще подписывать/диффать |

## S2 (Trust)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-33 | Trust backend | **`file` (SoftHSM-dev); `hsm` — заглушка до prod** | HSM сразу | HSM/quorum — внешний gate |
| D-34 | SoD | **отдельный `approver_token`; Admin ≠ approve; Approver ≠ kill-switch** | одна роль admin | требование S2 |
| D-35 | Approval policy | **policy add → pending approval; rollout требует approved** | rollout без approval | безопасность |
| D-36 | Backup | **zip: SQLite snapshot + trust dir** | только БД | ключи нужны для восстановления |
| D-37 | Key classes | **root/policy/model/driver/connector** | один ключ | разные классы — разные права |

## S3 (GUI)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-38 | GUI S3 | **web SPA (vanilla JS) на `/ui/`** | Tauri сразу | проверка UX/API без toolchain; Tauri — обёртка позже |
| D-39 | Токены в GUI | **sessionStorage, не файлы** | OS keychain | S3; mTLS/keychain — Tauri |
| D-40 | RBAC в UI | **role-specific токены, кнопки скрываются** | серые кнопки | SoD визуально |

## S4 (Learning)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-41 | Consent | **явный `consent=true`, иначе 403** | implicit opt-in | приватность |
| D-42 | PII-фильтр | **drop raw-полей + hash идентификаторов** | k-anonymity сразу | baseline; DPIA в финале |
| D-43 | Case labels | **TP/FP + holdout flag, `case_id` unique** | свободные метки | регрессия |
| D-44 | No-regression | **сравнение с active: TPR не ниже, FP не выше** | абсолютный порог | не терять качество |
| D-45 | Model slot | **active/previous на сервере; activate/rollback** | dual-slot на агенте сразу | S4 MVP |

## S5 (Scale)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-46 | Event bus MVP | **LocalBus; NATS — явная заглушка** | NATS сразу | нет сервера/клиента |
| D-47 | NATS при отсутствии | **явная ошибка, не тихий fallback** | молча LocalBus | не скрывать деградацию |
| D-48 | 1k-нагрузка | **1000 агентов, p95 111,6 мс** | 100 агентов | закрывает S5 load |

## S6 (Ops)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-49 | Metrics | **Prometheus text `/metrics` (admin)** | JSON-only | стандарт scrape |
| D-50 | Watchdog | **`scripts/stml_watchdog.py` + `/v0/slo`** | встроенный поток | внешняя независимость |
| D-51 | SLO snapshot | **`/v0/slo`: stats/audit/bus/targets** | отдельный сервис | MVP |

## S7 (Deploy)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-52 | Compose first | **Dockerfile + compose (SQLite volume)** | K8s сразу | малый парк |
| D-53 | K8s | **Helm chart reference; SQLite ReadWriteOnce** | PostgreSQL сразу | S1.5 |
| D-54 | Air-gapped | **процедура USB + anti-rollback + backup** | автоматический updater | S7 MVP |

## S8 (Coexistence / tenant)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-55 | Multi-tenant | **tenant_id в хранилище + фильтрация; один тенант на инсталляцию** | RLS/tenant-claim сразу | SQLite MVP |
| D-56 | EDR compat | **документированный режим, реализация в агенте** | STML-перехват | зона агента |
| D-57 | SIEM | **JSON + CEF export** | только JSON | совместимость |

## mTLS (S2 prod slice)

| # | Решение | Принято | Альтернативы | Почему |
|---|---|---|---|---|
| D-58 | mTLS | **сервер требует client cert (TLS 1.2+); коннектор — SSLContext** | HTTP + token | trust boundary |
| D-59 | Dev-сертификаты | **ECC P-256 CA/server/client, SAN 127.0.0.1** | RSA | быстрее генерация |
| D-60 | Production CA | **внешний CA + CRL/OCSP** | self-signed | отзыв/доверие |

## Открытые (предложены, не приняты)

| # | Вопрос | Варианты | Рекомендация |
|---|---|---|---|
| O-01 | `extra="forbid"` в `stml/v0` | forbid / ignore | forbid после S0.1b |
| O-02 | mTLS-спайк | Tauri / браузер + reverse-proxy / TUI+mTLS | решить по результату спайка |
| O-03 | Quorum HSM | 2-of-3 / 2-of-2 | 2-of-3 |
| O-04 | Event bus | NATS / Kafka | NATS, если нет Kafka |
| O-05 | Multi-tenant | RLS / schema-per-tenant | RLS до 10 |
| O-06 | DPIA-момент | финал / перед S4 | финал (принято владельцем) |
