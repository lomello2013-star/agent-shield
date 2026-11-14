# STML — инвентаризация источников (S0.0a, быстрый скан)

> Результат верификации по коду на 2026-11-14. Формат: «источник → да/нет/частично + подтверждение кодом».

## 1. RPC агента (`core/ipc.py`)

| # | Метод | Роль | Семантика (по коду) | Подтверждение |
|---|---|---|---|---|
| 1 | `ping` | viewer+ | `{"pong": true}` | `ipc.py:274-275, 324` |
| 2 | `health` | viewer+ | `daemon.health()` | `ipc.py:268-269, 325` |
| 3 | `stats` | viewer+ | `daemon.stats()` | `ipc.py:271-272, 326` |
| 4 | `self_test` | operator+ | `daemon.run_self_test()` | `ipc.py:277-281, 327` |
| 5 | `immutable_check` | operator+ | `verify_immutable()` → fingerprint immutable-политики | `ipc.py:320-322, 328` |
| 6 | `confirmations` | viewer+ | `daemon.pending_confirmations()` | `ipc.py:303-304, 331` |
| 7 | `confirm` | operator+ | `daemon.confirm(cid, decision, decided_by)` | `ipc.py:306-313, 330` |
| 8 | `quarantine` | operator+ | изоляция **объекта/файла** по `path` | `ipc.py:283-290, 329` |
| 9 | `kill_switch` | admin | kill **правила** по `rule_id` | `ipc.py:292-301, 332` |
| 10 | `shutdown` | admin | завершение агента (`daemon.stop`) | `ipc.py:315-318, 333` |

**Итого: 10 RPC.** `get_inventory`, `get_policy_state`, `suspend`, `resume` — **отсутствуют**.

## 2. Транспорт и аутентификация

| Аспект | Значение | Подтверждение |
|---|---|---|
| Сериализация | pickle | `ipc.py:16,159` |
| Транспорт | `multiprocessing.connection` (named pipe / AF_UNIX) | `ipc.py:22,130` |
| authkey | `AIDF_AUTHKEY` (hex) из env, иначе `os.urandom(32)` (ephemeral) | `scripts/aidf_service.py:139-140` |
| Лимит сообщения | 1 MiB | `ipc.py:27` |
| Роли | viewer / operator / admin | `ipc.py:324-333` |
| Токены | `AIDF_TOKEN` env / `--token-file` | `scripts/aidfctl.py:69,78` |

## 3. Файлы-источники (fallback для коннектора)

| Файл | Путь (root-относительный) | Подтверждение |
|---|---|---|
| audit chain | `audit/chain.jsonl` | `daemon.py:100` |
| quarantine | `quarantine.jsonl` | `daemon.py:115` |
| spool событий | `spool/events.jsonl` (через `spill_path`) | `daemon.py:118` |

## 4. Схемы и константы

| Источник | Статус | Подтверждение |
|---|---|---|
| `schemas/v3/` | есть | каталог JSON Schema |
| `MODELS_TRAIN_ON_DEVICE=False` | есть | эталон `core/policy.py`; зеркало `rust/src/policy.rs` |
| `aidfctl.py` | есть | `scripts/aidfctl.py` |

## 5. Разрыв контракта (что делать коннектору)

- `get_inventory` / `get_policy_state` отсутствуют → **fallback через `*.jsonl`**.
- `suspend` / `resume` отсутствуют → **серверный флаг** (не эмуляция через `kill_switch`/`shutdown`).
- `kill_switch` = kill правила, `shutdown` = остановка агента, `quarantine` = изоляция объекта — **разная семантика, не смешивать**.

## 6. Прочее

- **arm64:** не проверено на этой машине (x64); проверить явно в CI-матрице.
- **Rust-порт (`rust/`):** вне области STML на S0–S3 (решение владельца) — в пилоте только Python-агент.
- **authkey ephemeral:** если `AIDF_AUTHKEY` не задан, ключ случайный на каждый запуск → коннектор должен получать authkey из того же источника, что и `aidfctl`.

## 7. Вывод

`core/ipc.py` пригоден как источник для коннектора: 10 RPC, роли, pickle (локализуется), fallback-файлы есть. Следующий шаг — **S0.0b**: схема `stml/v0` + маппинг 5 ключевых RPC (enrolment, heartbeat, inventory, report, ack) + механика чтения `*.jsonl`.
