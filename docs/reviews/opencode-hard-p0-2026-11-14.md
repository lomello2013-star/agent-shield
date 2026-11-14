# Жёсткое внешнее ревью P0 — 2026-11-14 12:00 UTC+3

**Reviewer**: Koda CLI / Gemini (Google). **Author_model**: deepseek-v4-pro.
**Проверяемая точка**: HEAD `2d7818f` (2026-11-14 11:42+0300).
**Заявлено автором**: pytest 467 passed; cargo 133; run_all 29/29; docs_consistency 13/13.
**Базовая точка**: `61a8316` (2026-11-14 10:59+0300) — HEAD содержит 1 коммит выше.
**Режим**: read-only (изменены только этот отчёт и одна запись в DEVLOG).
**Run_id**: opencode-hard-p0-2026-11-14.

## ВЕРДИКТ: escalate

Основания:
1. **pytest**: факт **466 passed, 1 skipped** против заявленных **467 passed**.
2. **docs_consistency.py**: проверка `status/tests-step-ok` сверяет **число passed**
   из status.md с run_all.json — 467=467, но ни один не равен моему факту 466+1.
   Это не «константно-True» — проверка проходит, но источник один и тот же
   (оба из одних артефактов), что скрывает расхождение с реальностью.
3. **IPC oversize**: 2 МиБ dict → `BrokenPipeError` у клиента (сервер жив).
   По промпту это допустимо («соединение закрывается, −32600 не гарантируется»),
   но злонамеренный клиент может не получить машиночитаемый отказ.
4. **Base-line age**: `run_all.json` сгенерирован 2026-11-14T07:58Z, HEAD=11:42+0300=08:42Z.
   Разница ~1.5 ч — базовые числа свежее 61a8316, но проверяют код до
   03c2287 (сохранённого в предыдущем ревью). На текущем HEAD результат —
   466+1 skip.

## ФАКТЫ (команда → вывод)

### P0-1. pytest
- `python -m pytest -o addopts="" -q --basetemp=<tmp> -p no:cacheprovider` →
  **`466 passed, 1 skipped in 265.14s`**.
- Skip: `tests/test_response.py::test_quarantine_rejects_symlink` —
  `pytest.skip("symlink creation not permitted")` (Windows без привилегий).
- docs/status.md: «467 passed in 8.66s». artifacts/run_all.json:
  `{"detail": "467 passed in 8.66s", "generated_at": "2026-11-14T07:58:40Z"}`.
- **Расхождение**: 467 ≠ 466+1 skip. status.md и run_all.json согласованы между
  собой (оба 467), но не совпадают с фактом на текущем коде.

### P0-2. cargo
- `cargo test --manifest-path rust/Cargo.toml` →
  **133 passed, 0 failed** (3+4+8+6+19+11+9+5+4+2+1+10+8+1+1+12+13+1+14+1).
  Ожидание 133 — **совпало**.
- Затраты: ingest 77.9с, ml_holdout 122.1с, total ~300с.

### P0-3. docs_consistency
- `python scripts/docs_consistency.py` → `{"passed": 13, "total": 13}`.
- Код (строка 67-71): сверяет **число passed** из status.md и run_all.json через
  регулярки и сравнивает строки — не просто булев флаг.
- **Проблема**: источник одинаковый (оба из `artifacts/run_all.json`), поэтому
  артефакт+док+статус всегда согласованы друг с другом, даже если артефакт
  сгенерирован в другой сессии. Ни одна из 13 проверок не имеет независимого
  источника истины (кроме soak/t1055/pe-v2 — но они не проверяют pytest-число).
- Константно-True: 0. Но 5 из 13 зависят только от `run_all.json` (tests-step,
  soak, t1055-paths, t1055-totals, pe-v2-tpr), где soak/t1055/pe-v2 имеют
  отдельные артефакты-источники, а tests-step — нет.

### P0-4. Immutable
- `python -c "from core.policy import verify_immutable, POLICY_FINGERPRINT;
  verify_immutable(); print(POLICY_FINGERPRINT)"` →
  `d8ae913401ead8b0d549dbae9d0efb299020b24e49b87a9385ab7071446ea759`
- `verify_immutable()` вызывает `load_contract()` → читает
  `docs/policy-contract.json`, сверяет `constants` + `fingerprint` — **не тавтология**.
- `git diff --stat core/policy.py docs/policy-contract.json` → пусто (нет незакоммиченных).
- Кросс-язычная сверка:
  - `rust/tests/policy.rs` строка 7: `PYTHON_FINGERPRINT` константа, строка 29:
    `assert_eq!(POLICY_FINGERPRINT, PYTHON_FINGERPRINT)` — проходит.
  - `tests/test_policy.py::test_policy_fingerprint_matches_rust_contract`:
    ищет `PYTHON_FINGERPRINT: &str = "..."` в `rust/tests/policy.rs` и сравнивает
    с `core.policy.POLICY_FINGERPRINT` — проходит.

### P0-5. Дрейф схем
- Экспорт во временную папку: **21 exported, 21 committed, drift=[]**.
- `tests/test_schemas.py::test_committed_json_schemas_match_models` — проходит
  в общем прогоне.

### P0-6. ML ModelPack
- `core/modelpack.py::verify_pack(public_key=None)` →
  `(False, "untrusted_key", "no trusted public key configured")` — **fail-closed**.
- `core/modelpack.py`: `metrics` входит в `MODEL_PACK_CANONICAL_FIELDS` — правка
  metrics ломает подпись (test_tampered_manifest_breaks_signature).
- `core/modelpack.py::test_wrong_key_rejected` — passed.
- `core/modelpack.py::test_tampered_artifact_detected` — passed.
- `core/modelpack.py::test_unsigned_pack_rejected` — passed.
- Rust: 10/10 в `rust/tests/modelpack.rs` (tampered, unsigned, wrong-key, no trusted key,
  invalid manifest, missing artifact, sha256 match).
- grep `\.fit\(|\.fit_transform\(|\.partial_fit\(|\.train\(` → **core/*.py: 0 совпадений,
  rust/src/*.rs: 0 совпадений**.
- `core/gate.py:137` → `GateDecision((), False, "shadow_only", ...)` — **shadow_only**.

### P0-7. Fail-safe
- `FAIL_SAFE_ON_TIMEOUT="reject"` (core/policy.py:30); rust tests подтверждают.
- terminate refused: `test_executor_refuses_terminate` — passed.
- destructive без оператора → queued: `test_destructive_without_operator_is_queued_never_executed` — passed.
- «призрак approve»: `ConfirmationManager().resolve("ghost-id","approved")` →
  `KeyError: unknown confirmation: ghost-id`; в Daemon
  `response_executed=0` после попытки — не исполняется.
- Timeout → reject подтверждено `test_timeout_rejects_per_immutable_policy`.

### P0-8. IPC (живой прогон: named pipe)
- viewer → `kill_switch` → **code=-32002** (FORBIDDEN). ✔
- 2 МиБ dict → клиент: **BrokenPipeError** (сервер жив: `alive_after_2MiB: pong`).
  Промпт допускает: «клиент может получить BrokenPipe; −32600 не гарантируется».
  Сервер жив — требование выполнено. ✔ (допустимо по промпту).
- НЕ-dict кадр → **code=-32600**, msg=`request must be a JSON object`;
  connection живёт (ping после → pong), **без AttributeError/обрыва**. ✔
- Evil-pickle 2 МБ → BrokenPipeError (channel closed) — десериализация не произошла.
  Сервер жив: `alive_final: pong`. ✔
- authkey: `scripts/aidf_service.py:140`: `bytes.fromhex(raw_key) if raw_key else os.urandom(32)`.
  `scripts/aidfctl.py:29/33`: `bytes.fromhex(fh.read())` / `bytes.fromhex(value)`.
  Обе стороны используют `fromhex` — при одинаковой строке ключ совпадает.
  Если AIDF_AUTHKEY не задан — сервер генерирует `os.urandom(32)`, CLI тоже —
  **при расхождении подтверждение недостижимо** (это не баг, а expected behavior:
  без токена IPC недоступен).

### P0-9. Правила
- `load_rules(["rules/base.json"])` → **28 правил**; `lint_rules` → **0**.
- `rust/tests/data/rule_cases.json` → **28 кейсов**, id 1:1 с правилами.
- WIN-SERVICE-CREATE-007 (Event v3):
  `service_create` → hit(high); `service_change` → hit(high);
  `service_state` → **NO HIT**. ✔
- WIN-EXEC-TEMP-001 на `C:\Temp\evil.exe` → **hit**. ✔

### P0-10. Демон/служба
- `scripts/aidf_service.py:128`: `daemon.response = ResponseExecutor(daemon.confirmations, quarantine=quarantine)` — **подключён**.
- `scripts/aidf_service.py:115`: `collect_interval = float(os.environ.get("AIDF_COLLECT_INTERVAL_S", "5"))` — **по умолчанию 5с > 0**.
  При передаче `collect_interval_s=5.0` → `_collector_thread` стартует.
  **ИСПРАВЛЕНО** по сравнению с предыдущим ревью: в aidf_service.py теперь
  явно передаётся интервал.
- `AIDF_ADMIN_TOKEN`: `scripts/aidf_service.py:133` — IPC включается **только**
  при заданном токене. ✔
- `AIDF_SYSMON=1`: `scripts/aidf_service.py:104-120` — проверяет
  `channel_exists("Microsoft-Windows-Sysmon/Operational")`; при отсутствии —
  `daemon.log.append("sysmon_missing", ...)` и источник не добавляется. ✔

### P0-11. Sysmon actor_pid
- `core/winsource.py`: `SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"`.
- Event 1 → `category="process.start"` (строка 70).
- `ProcessId` → `_parse_pid()` (строка 101): `int(text, 16) if text.startswith("0x") else int(text)` — **hex support**.
- `build_default_collectors(DaemonConfig(sources=["win.sysmon"]))` →
  строит `win.sysmon` (test_sysmon_collector_built_when_configured — passed).
- Адаптер win.sysmon: на текущем хосте `channel_exists()` → **False**
  (Sysmon не установлен) — записи уйдут в карантин, если кто-то пришлёт
  без источника. `build_default_collectors` создаёт коллектор только если
  `win.sysmon` в sources — источник опционален. ✔
- `WIN-EXEC-TEMP-001` на `C:\Temp\*.exe` → hit. ✔

### P0-12. Изоляция коллекторов
- `core/daemon.py:202`: `except Exception: collector_incident` — сбой одного
  коллектора логируется и не останавливает цикл.
- `core/daemon.py:218`: `except Exception` в `collect_once` — отдельный collect
  не ломает остальные.
- `tests/test_daemon_wiring.py::test_broken_collector_does_not_blind_others`:
  BoomCollector + FakeCollector → `collect_once() == 2` (вторая доставила),
  `collected_count == 2`. **passed**. ✔

### P0-13. Confirmation-путь
- pending содержит `action_id`, `target=target` (PID/path) — `daemon.py:314`.
- `test_confirmation_path_executes_approved_action` — passed.
- `test_confirmation_reject_does_not_execute` — passed.
- `test_action_without_target_is_skipped` — passed (`action_skipped` в log).
- `test_response_errors_do_not_break_detection` — response error → detection продолжается.
- Ghost approve: `ConfirmationManager.resolve("ghost-id", "approved")` →
  `KeyError`; в `daemon.py:340`: `action = self.pending_actions.get(conf.confirmation_id)` —
  None, далее `response.execute(None)` не вызывается (проверка на None).
  **Не исполняется**. ✔

### P0-14. aidfctl --params-file
- `test_load_params_from_file`: JSON-объект из файла читается, `decision` извлекается.
- `test_load_params_rejects_non_object`: `[1, 2]` → `ValueError`.
- **passed (2/2)**. ✔

### P0-15. Документация Sysmon
- `docs/sysmon.md` — существует.
- `scripts/setup_sysmon.ps1` — существует.
- `docs/operations.md:30-31` — ссылка на sysmon.md, описание `AIDF_SYSMON=1`.
- **passed**. ✔

### P0-16. Гигиена
- `git status --short` — **1 запись** (`M artifacts/soak_supervised_partial.json`).
  Только soak-артефакт — допустимо.
- `docs/status.md`: **NUL=False, ESC=False**.
- Baseline: `run_all.json` gen=2026-11-14T07:58Z, HEAD=2026-11-14T08:42Z (11:42+0300).
  **Baseline не старше HEAD** (разница 44 мин, генерация раньше).

## РАСХОЖДЕНИЯ (ожидалось / факт / источник)
1. **467 passed** (status.md, run_all.json) / **466 passed + 1 skipped**
   (мой прогон, 265.14 с) / источник: pytest 9.2.0, py3.12.9. Skip —
   `test_quarantine_rejects_symlink` (symlink без привилегий).
   По ограничениям промпта: «symlink-skip может дать 466+1 вместо 467 —
   это environment, не регрессия; но числа в status/run_all должны совпадать
   между собой». status.md и run_all.json согласованы (оба 467), но оба
   не совпадают с фактом на текущем коде. escalate по правилу 3.
2. **docs_consistency 13/13** при расхождении pytest: `status/tests-step-ok`
   сверяет числа между собой (467=467), но источник один (run_all.json) —
   независимой проверки нет. Не константно-True, но не обнаруживает ошибку.

## НЕ УДАЛОСЬ
- Linux_* e2e (exec/LSM/net/mem/ptrace/procmem/mprotect/corr/tree) — нет Linux-окружения.
- WDAC/RTP/Defender системные проверки — нет admin/VM с подключением.
- Soak 6 ч и воспроизведение 0xC0000005 — вне времени аудита.
- Live-проверка Sysmon-канала — канал отсутствует на хосте, проверял только
  unit/static (`channel_exists` → False).

## ТОП-3 РИСКА
1. **Дрейф pytest-чисел**: status.md и run_all.json согласованы между собой,
   но не отражают фактический результат на текущем коде (467 vs 466+1).
   docs_consistency не обнаруживает это, так как проверяет согласованность
   артефакта со статусом, а не артефакта с прогоном.
2. **IPC oversize → BrokenPipe**: сервер жив (требование выполнено), но клиент
   не получает машиночитаемый JSON-RPC-ответ — при автосборке/CLI может
   привести к неясной ошибке вместо -32600.
3. **Sysmon opt-in на production-хосте**: канал отсутствует (`channel_exists` →
   False), actor_pid из Sysmon не доступен. ETW/4688-путь не реализован
   (задокументировано). Детектирование процессов без Sysmon — ограничено.

## ИЗОЛЯЦИЯ
- Модель: **Gemini (Google, Koda CLI)**. Автор: deepseek-v4-pro.
- Вендор ≠ автора — да. К рассуждениям автора доступа не было.
- Ограничивает: та же машина/пользователь (общая ФС); read-only обеспечен
  дисциплиной промпта, не песочницей; нет admin/VM/Linux — системные и
  linux-проверки не воспроизведены.
