# Контракт Rust-порта (F19)

> Статус: **12/12 модулей покрыты кодом**, 133 Rust-теста, 0 clippy warnings. `ml` использует `tract-onnx` + `ort`; полный 50k holdout пройден (`max_abs_diff=0`). `ipc` имеет Python-wire TCP, Windows named pipe и Unix AF_UNIX (authkey + pickle framing, проверено Python-клиентами). `confirm` портирован; SHA-256 — из `sha2`. `rustc`/`cargo` установлены, блокер E снят. Документ фиксирует, **что** портируется, чтобы порт был механическим, а не переосмыслением. Код: [`rust/`](../rust/README.md).

## 1. Принцип

Порт — не переписывание архитектуры, а перенос уже измеренных контрактов. Python-версия остаётся эталоном поведения: её артефакты (`artifacts/*.json`) — приёмочные тесты для Rust.

## 2. Модули и типы

| Модуль Python | Что переносится в Rust | Тип Rust (проект) | Критерий эквивалентности |
|---|---|---|---|
| `core/policy.py` | immutable-константы + fingerprint | `const` + `&'static str` | `POLICY_FINGERPRINT` совпадает побайтово |
| `core/clock.py` | монотонные часы, детекция скачка | `struct MonoClock` | тот же тест: jump > threshold → событие |
| `core/counters.py` | счётчики потерь/overflow/backlog | `struct Counters` (атомики) | те же инварианты `ledger_ok` |
| `core/heartbeat.py` | warn/escalate/timeout | `struct Heartbeat` | те же 3 порога, `degraded`/`stalled`/`silent` |
| `core/ingest.py` | P0/P1/P2, резерв ёмкости, spill | `enum Priority`, `struct Ingest` | 0 потерь на 100k, тот же spill |
| `core/rules.py` | правила как данные, окна, корреляция | `struct Rule`, `struct Correlator` | те же 28 правил, те же фикстуры |
| `core/gate.py` | severity→action, бюджет, PPV | `enum Severity`, `fn ppv` | тот же `observe_only` для low/medium |
| `core/response.py` | suspend/resume, карантин AES-GCM | `trait ReversibleAction` | suspend p95 в том же порядке |
| `core/modelpack.py` | Ed25519-подпись, fail-closed | `struct ModelPack` (ring/ed25519) | пак отклоняется при неверной подписи |
| `core/ml.py` | ONNX-инференс, shadow | `struct ShadowDetector` (ort) | те же скоры ±1e-4 |
| `core/selfprotect.py` | хеш-цепочка аудита | `struct AuditChain` | verify 20k, tamper detect 5/5 |
| `core/ipc.py` | JSON-RPC, роли | `struct RpcServer` | те же коды и авторизация |

## 3. Что НЕ портируется (осознанно)

- eBPF-программы остаются на C с libbpf: у Rust-загрузчика нет преимуществ, а CO-RE-код уже измерен.
- Драйвер ядра не пишется ни на Python, ни на Rust: уровень C, нужна подпись (блокеры A/B).
- Обучение моделей — офлайн-скрипты; на устройстве обучение не добавляется (immutable).

## 4. Порядок порта (при разблокировке E)

1. `policy` + `clock` + `counters` (нет зависимостей) → приёмочный тест: fingerprint + тесты. — ✅ 2026-11-13: 21 тест, `POLICY_FINGERPRINT` совпадает.
2. `heartbeat` + `ingest` → приёмочный тест: R2-пороги и 0 потерь. — ✅ 2026-11-13: 20 тестов.
3. `rules` + `gate` → те же 28 правил и фикстуры (данные копируются как JSON). — ✅ 2026-11-13: 32 теста.
4. `modelpack` + `ml` → те же паки, паритет ±1e-4. — ✅ `modelpack` 10 тестов; `ml` 7 тестов, полный 50k holdout через `ort` (`max_abs_diff=0`); `tract` — медленный fallback.
5. `response` + `selfprotect` + `ipc` → те же измерения p95 и tamper. — ✅ `response` 13 (включая реальный suspend), `selfprotect` 14, `ipc` 7 (Python TCP/named pipe/AF_UNIX); `confirm` 8.

## 5. Критерий готовности порта

Все артефакты из `artifacts/` воспроизводятся Rust-версией в пределах заявленных допусков; Python-версия остаётся доступной как эталон до полной замены. Несоответствие хотя бы одного артефакта — блокер релиза порта.
