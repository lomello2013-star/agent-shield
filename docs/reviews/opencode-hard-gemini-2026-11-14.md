# Жёсткое внешнее ревью P0 — 2026-11-14

**Reviewer**: Koda CLI / Gemini (Google). **Author_model**: deepseek-v4-pro.
**Режим**: read-only (изменены только этот отчёт и одна запись в DEVLOG).
**Run_id**: opencode-hard-2026-11-14.

## ВЕРДИКТ: escalate

Основания (любое расхождение → escalate по правилам промпта):
1. pytest: факт **459 passed, 1 skipped** против заявленных **460 passed** в
   docs/status.md и artifacts/run_all.json.
2. IPC: кадр 2 МиБ — клиент получает **BrokenPipeError**, а не обещанный
   JSON-RPC −32600 (сервер жив, но протокольная гарантия не выполнена).
3. Демон: рабочий сервис `scripts/aidf_service.py` **не опрашивает коллекторы**
   (`collect_interval_s=0.0` по умолчанию → поток сборщиков не стартует).

## ФАКТЫ (команда → вывод)

### P0-1. pytest
- `python -m pytest -o addopts="" -q` (первый прогон) → **крах sessionfinish**:
  `PermissionError [WinError 5]` в `pytest-of-lomel` (cleanup), финальная строка
  не напечатана, exit≠0.
- Повтор с `--basetemp=<tmp> -p no:cacheprovider`:
  **`459 passed, 1 skipped in 182.47s`** (стабильно: 191.26s во втором прогоне).
- Skip: `tests/test_response.py::test_quarantine_rejects_symlink` (создание
  symlink не разрешено без привилегий).
- docs/status.md и run_all.json (gen 2026-11-13T21:42Z): «460 passed in 12.45s».
  460 ≠ 459 passed + 1 skipped по формулировке; baseline сгенерирован до
  коммитов 518fe58 (00:43) и 03c2287 (01:14).

### P0-2. cargo
- `cargo test --manifest-path rust/Cargo.toml` → суммарно
  **133 passed; 0 failed** (3+4+8+6+19+11+9+5+4+2+1+10+8+1+1+12+13+1+14+1).
  Ожидание 133 — **совпало**.

### P0-3. docs_consistency
- `python scripts/docs_consistency.py` → `{"passed": 13, "total": 13, "failed": []}`.
- Слабые места (по коду scripts/docs_consistency.py):
  - `status/tests-step-ok` проверяет только флаг `ok` шага tests в run_all.json,
    **не сравнивая число passed** с фактическим прогоном — именно поэтому
    460 vs 459+1 не детектируется;
  - 4 проверки (`t1055-md/paths`, `t1055-md/layers`, `matrix/detection`,
    `matrix/prevention`) сравнивают док с *артефактом*, а не с реальностью;
    при согласованно протухшей паре док+артефакт они True ложно;
  - ни одна из 13 проверок не является буквально константно-True, но 5 из 13
    не имеют независимого источника (все идут из тех же артефактов).
- Побочный эффект запуска: перезаписан `artifacts/docs_consistency.json`
  (git diff: только `generated_at`).

### P0-4. Immutable
- `python -c "from core.policy import verify_immutable, POLICY_FINGERPRINT;
  verify_immutable(); print(POLICY_FINGERPRINT)"` →
  `d8ae913401ead8b0d549dbae9d0efb299020b24e49b87a9385ab7071446ea759`
  (совпадает с docs/policy-contract.json и status.md d8ae913401ea).
- `verify_immutable()` читает **внешний** `docs/policy-contract.json`
  (`load_contract()`), сверяет значения И fingerprint контракта с константами
  модуля → **не тавтологичен**; тест
  `test_verify_immutable_rejects_contract_fingerprint_drift` подтверждает.
- `git diff --stat core/policy.py docs/policy-contract.json` → пусто (нет
  незакоммиченных изменений).
- Кросс-язычная сверка: `tests/test_policy.py::test_policy_fingerprint_matches_rust_contract`
  существует и проходит; замечание: это **текстовый** поиск литерала
  `PYTHON_FINGERPRINT` в `rust/tests/policy.rs`, а не исполнение Rust; реальная
  кросс-язычная проверка — `rust/tests/policy.rs::fingerprint_matches_python_artifact`
  (тоже проходит, 8/8 в policy.rs).

### P0-5. Дрейф схем
- `export_json_schemas()` во временную папку + побайтовое сравнение:
  **exported 21 = committed 21, drift = []**.
- Drift-guard: `tests/test_schemas.py::test_committed_json_schemas_match_models`
  существует и прошёл в общем прогоне.

### P0-6. DEVLOG ↔ артефакты (12 сверок)
| # | Запись DEVLOG/status | Артефакт | Число | Совпало |
|---|---|---|---|---|
| 1 | 460 passed | run_all.json | «460 passed in 12.45s» | с артефактом да; **с моим прогоном нет (459+1 skip)** |
| 2 | soak 35653 событий | soak_report.json | 35653 | да |
| 3 | T1055 400/400/0 | t1055_coverage.json | 400/400/0 | да |
| 4 | 28 правил, 100/100 % | stage5_report.json | detection/prevention 100.0 | да |
| 5 | 7705.0 записей/с | stage4_report.json | records_per_s=7705.0 | да |
| 6 | R2 59.5 с | stage1_report.json | max/p95_latency_s=59.5 | да |
| 7 | chaos 80 verdicts, loss 0 | stage12_chaos.json | verdicts_after_sources=80 | да |
| 8 | PE v2 TPR@0.05 % FPR | pe_v2_report.json | 0.67242 | да |
| 9 | supervisor restarts | supervisor_measure.json | restart latency 282.5 мс | да |
| 10 | docs_consistency 13 | docs_consistency.json | passed=13 | да (файл пересоздан моим прогоном) |
| 11 | IPC health p95 1.884 мс | ipc_report.json | ms_p95=1.884 | да |
| 12 | 0xC0000005, R1/R4 не подтверждены | f11_health_probe_summary.json | прогоны без stall; краш не воспроизведён | формулировка честная |

Несошедшееся: только п. 1 (в части соответствия документированного числа
фактическому прогону на текущем коде).

### P0-7. ML
- `core/modelpack.py::verify_pack`: `public_key is None` →
  `(False, "untrusted_key")` — fail-closed.
- Тесты Python (tests/test_modelpack.py, 10) и Rust (rust/tests/modelpack.rs, 10):
  tampered artifact / tampered manifest / unsigned / wrong key / missing
  artifact / no trusted key / invalid manifest — все passed.
- `metrics` входит в canonical payload (MODEL_PACK_CANONICAL_FIELDS) → правка
  metrics ломает подпись (test_tampered_manifest_breaks_signature).
- grep `\.fit(|\.fit_transform(|\.partial_fit(|\.train(` по `core/*.py` и
  `rust/src/*.rs` → **0 совпадений**; доп. guard —
  `test_no_training_calls_in_runtime_core`.
- shadow_only: `core/gate.py` → `GateDecision((), False, "shadow_only", ...)`
  для модельных вердиктов.

### P0-8. Fail-safe
- `FAIL_SAFE_ON_TIMEOUT="reject"`; timeout→reject: py + rust тесты passed.
- terminate refused: `test_executor_refuses_terminate` passed.
- destructive без оператора → queued, never executed: py+rust passed.
- «призрак approve»: `ConfirmationManager().resolve("ghost-id","approved")` →
  `KeyError: unknown confirmation: ghost-id`; в Daemon `response_executed=0`
  после попытки — не исполняется.

### P0-9. IPC (живой прогон: RpcServer + raw-клиенты, именованный канал)
- viewer → `kill_switch` → **−32002** (FORBIDDEN). ✔
- кадр-не-dict (валидный pickle строки) → **−32600** «request must be a JSON
  object», соединение живёт (ping после — pong), без AttributeError/обрыва. ✔
- лимит до десериализации: evil-pickle 2 МБ → сервер **не** десериализовал
  (`__reduce__` не вызван, процесс жив), соединение разорвано. ✔
- **2 МиБ dict → клиент получил `BrokenPipeError [WinError 109]`, а НЕ −32600.**
  Сервер жив (`alive_after_2MiB: {'pong': True}`), но обещанный ответ
  «request too large» на клиент не доходит: `recv_bytes(maxlength)` рвёт
  дескриптор с обеих сторон до `_send`. Формулировка промпта
  «2 МиБ dict → −32600 и сервер жив» выполнена наполовину. ✘

### P0-10. Правила
- `load_rules(["rules/base.json"])` → **28 правил**; `lint_rules` → **0** замечаний.
- Фикстуры: `rust/tests/data/rule_cases.json` → **28** кейсов, id 1:1 с правилами
  (parity-тест py+rust passed).
- WIN-SERVICE-CREATE-007 (живой прогон на Event v3):
  `service_create` → hit(high); `service_change` → hit(high);
  `service_state` → **NO HIT**; `start` → NO HIT. ✔ (regex `(?i)service` удалён,
  теперь `"in": ["service_create","service_change"]`).

### P0-11. Демон
- `DaemonConfig.sources` по умолчанию `["win.eventlog","win.defender"]`;
  коллекторы **реализованы** (`core/winsource.WindowsEventLogSource`,
  `build_default_collectors` строит оба на win32, poll() реально читает wevtutil —
  100 записей в моём прогоне).
- `ResponseExecutor`/quarantine **подключены** в `scripts/aidf_service.py`
  (`daemon.response = ResponseExecutor(...)`, `response_quarantine`).
- **ОТКРЫТЫЙ ПУНКТ (P0):** `Daemon(..., collect_interval_s=0.0)` — дефолт;
  сервис не передаёт интервал; `daemon.start()` при 0.0 поток сборщиков НЕ
  запускает (факт: `_collector_thread=None` после start); рабочий цикл сервиса
  зовёт только `tick()`, который не вызывает `collect_once()`.
  ⇒ в сервисном режиме события с хоста не собираются вообще; «измеренные»
  e2e-цифры получены харнессами, которые интервал выставляют явно
  (tests/test_daemon_wiring.py использует 0.01).

### P0-12. Гигиена
- `git status --short` до аудита: **1** запись (M artifacts/soak_supervised_partial.json).
  После: **2** (+ artifacts/docs_consistency.json — неизбежный побочный эффект
  обязательного запуска docs_consistency.py; diff только в generated_at).
- `b"\x00" in open("docs/status.md","rb").read()` → **False**.
- Baseline: run_all.json/status.md сгенерированы 2026-11-13T21:42Z; HEAD=03c2287
  (2026-11-14 01:14+0300 = 22:14Z) ⇒ baseline **моложе не всех** изменений
  (два последних коммита его новее).

## РАСХОЖДЕНИЯ (ожидалось / факт / источник)
1. **460 passed** (docs/status.md, run_all.json) / **459 passed + 1 skipped**
   (мой прогон ×2) / источник: pytest 9.2.0, py3.12.9. Skip — symlink без
   привилегий; baseline, вероятно, снят в привилегированной сессии.
2. **2 МиБ → −32600 и сервер жив** (промпт P0-9) / **BrokenPipeError у клиента,
   сервер жив** / core/ipc.py::_recv_frame + живой прогон.
3. **«Коллекторы подключены к демону»** (подтекст status/DEVLOG о рабочем
   сервисе) / **в сервисном цикле опроса нет (collect_interval_s=0.0)** /
   scripts/aidf_service.py + core/daemon.py::_start_collectors.
4. docs_consistency=13/13 при п. 1 — проверка `status/tests-step-ok` сверяет
   только булев флаг, а не число: 13/13 не покрывает главное расхождение.

## НЕ УДАЛОСЬ
- Первый прогон pytest в стандартный basetemp — PermissionError WinError 5
  (заблокированный pytest-of-lomel); обошёл через чистый `--basetemp`.
- linux_*-e2e (exec/LSM/net/mem/ptrace/procmem/mprotect) — нет Linux-окружения
  в этой сессии; артефакты не перепроверялись.
- WDAC/RTP/Defender-системные проверки и установка политик — нет admin.
- Soak 6 ч и воспроизведение 0xC0000005 — вне времени аудита.

## ТОП-3 РИСКА
1. **Сервис не собирает события**: в штатном режиме (`aidf_service.py`) поток
   коллекторов не запускается (`collect_interval_s=0.0`), детектирование
   мертво, хотя все e2e-харнессы зелёные. Расхождение «измерено» vs «работает».
2. **Незакрытый нативный краш 0xC0000005** на длинных прогонов (сам статус это
   признаёт: R1/R4 не подтверждены) + baseline статусов отстал от HEAD;
   460 vs 459+1 — симптом того же дрейфа.
3. **IPC oversize**: разрыв канала вместо протокольной ошибки оставляет клиента
   без машиночитаемого отказа; при pickled-транспорте любой сбой рамки —
   молчаливый DoS на соединение.

## ИЗОЛЯЦИЯ
- Модель: **Gemini (Google)**; автор — deepseek-v4-pro. Вендор ≠ автора — да.
- Свежий контекст — да; к рассуждениям автора доступа не было (только файлы
  репозитория, включая ранее сохранённые отчёты ревью — они читались как
  данные, гипотезы из них перепроверялись прогонами).
- Ограничивает: та же машина/пользователь, что и автор (общая ФС, общий git);
  read-only обеспечен дисциплиной, не песочницей; нет admin/VM ⇒ системные и
  linux-проверки не воспроизведены.
