# Rust-порт AIDefender (F19)

Порт покрывает все 12 модулей контракта; Python-версия остаётся эталоном поведения. Rust-код проверяется собственными тестами и паритетом ключевых контрактов. Полная wire-совместимость IPC и полный ML-holdout — отдельные ограничения ниже.

## Статус

| Модуль | Rust | Тесты |
|---|---|---|
| `policy` | ✅ immutable-константы, canonical JSON, fingerprint, `verify_immutable` | 8 + 3 SHA |
| `clock` | ✅ `TimeSource`, `MonotonicClock`, `ClockJump` | 4 |
| `counters` | ✅ `LossCounters`, callback, снимок, конкурентность | 6 |
| `heartbeat` | ✅ пороги warn/escalate, probe, incidents | 11 |
| `ingest` | ✅ P0/P1/P2, reserved headroom, агрегация, spill/replay, ledger | 9 |
| `gate` | ✅ PPV, budget, suppression, kill-switch, critical bypass | 19 |
| `rules` | ✅ 28 правил, окна, корреляция, lint; `fancy-regex` для lookahead | 14 |
| `modelpack` | ✅ Ed25519, canonical payload, hash, fail-closed | 10 |
| `selfprotect` | ✅ hash-chain, anchor, integrity manifest, self-test | 14 |
| `response` | ✅ AES-256-GCM quarantine/restore, canary, suspend/resume, executor; suspend/resume проверен на реальном процессе | 13 |
| `confirm` | ✅ портирован `core/confirm.py`: timeout→reject, очередь без оператора, идемпотентность | 8 |
| `ml` | ✅ `tract-onnx` + `ort`; PE model, linear quantile, shadow detector; 50-строчный и **полный 50k** holdout | 7 |
| `ipc` | ✅ JSON-RPC dispatch/roles; Python-wire TCP, Windows named pipe и Unix AF_UNIX (authkey + pickle framing) | 7 |

**Всего:** 133 Rust-теста, `cargo fmt --check` и `cargo clippy -D warnings` чистые.

## Запуск

На этом хосте нет Visual Studio Build Tools, поэтому используется `rust-lld` из toolchain и библиотеки Windows SDK:

```powershell
.\rust\run-tests.ps1
```

Скрипт находит свежий Windows SDK, выставляет `LIB` и `RUSTFLAGS`, затем запускает `cargo test`.

Полный 50k holdout требует данных (476 МБ, не коммитятся). Сгенерировать:

```powershell
python .\rust\export_holdout.py
.\rust\run-tests.ps1
```

`ml_holdout_full` пропускается, если `rust/target/pe_holdout_50k` отсутствует.

## Gate и бенчмарк

```powershell
.\rust\gate.ps1          # fmt + clippy + 133 теста; artifact rust_gate.json
cargo run --bin bench    # rules/ingest/gate; artifact rust_bench.json
cargo run --release --bin bench  # release-цифры
```

`gate.ps1` не трогает Python-файлы и не запускает `run_all`, поэтому не конфликтует с основным агентом.

Release-бенчмарк: rules **24 034 соб./с**, ingest 100k за **0,0445 с**, gate 100k за **0,0458 с** (2,18 млн решений/с). Debug: 7 568 / 0,119 / 0,207.

Если MSVC Build Tools установлены:

```powershell
cargo test --manifest-path .\rust\Cargo.toml
```

## Зависимости

| Крейт | Зачем |
|---|---|
| `serde`, `serde_json` | JSON-контракты, spill, audit log, manifests |
| `uuid` | verdict/event/quarantine ids |
| `regex`, `fancy-regex` | правила; `fancy-regex` нужен для negative lookahead в `WIN-MASQUERADE-011` |
| `ed25519-dalek` | проверка подписи ModelPack |
| `aes-gcm` | карантин AES-256-GCM |
| `chrono` | RFC3339-время audit-цепочки |
| `serde-pickle`, `hmac`, `sha2` | Python `multiprocessing.connection` handshake (`authkey`) и pickle framing |
| `tract-onnx` | ONNX-инференс без внешнего runtime |
| `ort` | быстрый ONNX Runtime backend для полного 50k holdout |
| `interprocess` | local socket: named pipe (Windows) / AF_UNIX (Linux) |
| `libloading` (Windows) | `NtSuspendProcess`/`NtResumeProcess` без `windows-sys` |
| `windows-sys` (Windows) | message-mode named pipe для Python interop |
| `libc` (Linux) | SIGSTOP/SIGCONT |

## Ограничения

- **`ipc`**: Python-wire TCP, Windows named pipe и Unix AF_UNIX проверены; AF_UNIX — отдельным mini-crate в WSL (`rust/unix_ipc_test`).
- **`ml`**: полный 50k holdout пройден через `ort` (`max_abs_diff = 0`, ~7,5 с); `tract` остаётся медленным fallback.
- `response::ResponseExecutor` теперь может использовать портированный `ConfirmationManager`; trait `ConfirmationGate` сохранён для тестов.
- SHA-256 — из крейта `sha2`.
- `run-tests.ps1` / `gate.ps1` — Windows-only обход отсутствия MSVC linker.

## Критерий готовности полного порта

Все артефакты `artifacts/*.json` воспроизводятся Rust-версией в пределах заявленных допусков, включая ONNX-паритет и IPC-авторизацию. Python-версия остаётся доступной как эталон до полной замены.
