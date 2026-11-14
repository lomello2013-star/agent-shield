# Threat model — Agent Connector (S0.1b)

> Mini-threat model T1-компонента. Статус: **принята делегированно** (AI-агент
> под human-approval заказчика); финальная human-подпись — на production-приёмке.

## 1. Активы

- Данные агента: health, stats, audit/quarantine/spool.
- Буфер отчётов (SQLite) и его целостность.
- Ключ подписи пакета коннектора (`key_id`).
- Локальный JSON-RPC endpoint (порт/токен).

## 2. STRIDE

| Угроза | Вектор | Митигация S0.1b | Остаточный риск |
|---|---|---|---|
| **S**poofing | поддельный клиент JSON-RPC | loopback-only + `auth_token` в каждом запросе; lock 0600 | токен в lock-файле; ACL ОС |
| **T**ampering | подмена `*.jsonl` / SQLite | read-only чтение; SQLite integrity; ACL буфера | локальный админ |
| **R**epudiation | отрицание отправки | append-only audit агента + `report_id` | нет отдельного локального audit коннектора (S1) |
| **I**nformation disclosure | утечка raw-логов | нормализация `stml/v0`, PII-фильтр (S4) | raw payload в `Report.payload` пока есть |
| **D**oS | переполнение буфера | лимит 10k строк, purge 7 дней, P0 защищён | диск |
| **E**levation | лишние права | отдельный пользователь, loopback, ACL | user-mode |
| **Replay** | повтор отчёта | `report_id` + nonce; серверная проверка — S1 | до S1 |
| **Format drift** | смена схемы агентом | `schema_version`, degraded-алерт | — |
| **Pickle-RCE** | вредоносный pickle | только доверенный endpoint, authkey, 1 MiB, валидация типов | authkey в памяти |

## 3. Контроли S0.1b (реализованы)

1. **ACL:** lock/state/spool — `chmod 0600` (POSIX) / `icacls` текущему пользователю (Windows), best-effort.
2. **Auth token:** `ConnectorRpcServer(auth_token=...)`; без токена — `unauthorized`; токен в lock-файле под ACL.
3. **Package signing:** Ed25519; `key_id` = sha256(pubkey)[:16]; манифест файлов + подпись; проверка при старте (`--package-manifest/--package-pubkey/--package-root`), при ошибке — exit 2.
4. **5 read-only RPC:** `ping`, `health`, `stats`, `self_test`, `immutable_check` — только чтение, без команд.
5. **P0:** не вытесняется; retry с backoff.

## 4. Остаточные риски (приняты)

| Риск | Статус |
|---|---|
| Компрометация ОС до установки | принят, не покрыт |
| Локальный администратор | принят, не покрыт |
| Утечка authkey из памяти | принят, ротация |
| Supply chain ключа | частично: отзыв в S2 |
| Raw payload в отчёте | принят до S4 (PII-фильтр) |

## 5. Приёмка

- [x] STRIDE заполнен.
- [x] Контроли реализованы и покрыты тестами (25 STML-тестов).
- [x] Остаточные риски перечислены.
- [ ] Финальная human-подпись (production-приёмка).
