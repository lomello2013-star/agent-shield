# Независимое ревью: deepseek-flash (субагент, свежий контекст)

> **Дата:** 2026-11-13. **Вердикт:** **escalate**.
> **Изоляция:** reviewer = `deepseek-flash`, author = `deepseek-v4-pro` — формально `reviewer_model != author_model`, но та же семья/вендор; изоляция слабее §3 `auto-reviewer-spec` (ожидается другая модель, в промпте для OpenCode назван GLM-5.3-Flash). Доступа к рассуждениям автора не было: только репозиторий + задание; DEVLOG читался как утверждения и проверялся артефактами/прогонами.

## Вердикт: escalate

Причина: **P0-число набора тестов не воспроизводится** (заявлено 655 passed / 1 skipped = 656; фактически **661 passed / 0 skipped**), плюс в окружении 3.14.10 набор красный (**660 passed / 1 failed**). По правилу «числа расходятся с заявленными» → escalate. Отдельно: изоляция ревьюера по §3 не выполнена.

## Проверено (с числами)

1. **pytest, 3.12.9:** 661 passed, 0 skipped, 8,56–9,57 с, exit 0 (3 повтора). В `.venv314` / `.venv314c`: 660 passed, 1 failed — падает `tests/test_response.py::test_suspend_and_resume_real_process` (воспроизведено 3/3). Причина измерена: venv-redirector 3.14 порождает реальный интерпретатор как child; `suspend(заглушка)` = 52→72 байта (не держит), `suspend(реальный pid)` = 72→72 (держит). Это ограничение «suspend по pid без потомков», не поломка кода.
2. **cargo test:** 133 passed, 0 failed; 21 тест-бинарь.
3. **docs_consistency:** 15/15, но **2 из 15 — безусловные True** (devlog/field-coverage, devlog/auto-review-disclosed), число тестов намеренно не сверяется → не 15 независимых проверок.
4. **Immutable:** `verify_immutable()` → None; fingerprint `d8ae9134…` совпал; `git diff core/policy.py` пуст; 4 константы верны. **Но** `verify_immutable()` тавтологичен (снимок против себя), `run_all` только печатает префикс fingerprint, не сверяя с эталоном; реальная защита — жёсткие assert'ы в `tests/test_policy.py:9-13` и литерал в `rust/tests/policy.rs:7` (кросс-сверки Python↔Rust нет).
5. **Схемы:** 21 сгенерировано, 21 в репозитории, 0 byte-different, 0 семантически разных; drift-guard есть.
6. **ML ModelPack (9 кейсов):** valid→ok; tampered→`hash_mismatch`; unsigned→`invalid_manifest`; чужой ключ→`signature_invalid`; public_key=None→`untrusted_key`; правка metrics/limits→`signature_invalid`; нет файла→`missing_artifact`. `fit`/`train` в runtime — 0 вхождений. Gate: `detector!="rule"` → actions=(), alert=False; actions_taken=0.
7. **Fail-safe (пробник):** таймаут 30 с → reject, executable False; истёкшее подтверждение → refused; destructive без оператора → queued; «призрак» approve остаётся pending, expire не трогает; terminate → refused; block_network/unblock → failed.
8. **IPC:** viewer→kill_switch = −32002 FORBIDDEN; viewer→quarantine = −32002; admin→kill_switch = ok; запрос 2 МиБ → −32600 за 9–10 мс, соединение живо, accept-thread жив.
9. **Правила:** 28 правил, 28 фикстур (0 без, 0 сирот), все срабатывают на своих фикстурах, 0 на benign; lint=[]; 3 корреляционных, 1 оконное; prevention=true у 22/28.
10. **DEVLOG↔артефакты, 12 сверок:** точно сошлись soak 1 ч (3600,2 с/0/100 %/15 612 записей), soak_before_reboot 2284,8 с, soak_before_hyperv 1623,5 с, ETW-TI rc 0x80070005, WDAC 120/112/8/5, f11_controls 0xC0000005; живьём RTP True, Behavior True, AIDefender Running/Automatic, AIDF-Soak24 Running, Secure Boot True, Hyper-V Enabled.

## Не сошлось

- **P0-1 (главное):** 655 passed / 1 skipped → факт 661 passed / 0 skipped. `tests/test_supervisor.py` (untracked, 7 тестов) объясняет часть; `-q` в `addopts` + второй `-q` = `-qq`, подавляющий итоговую строку — вероятный источник дрейфа.
- **DEVLOG 22:45:** «655 passed, 1 failed» на 3.14 → фактически **660 passed, 1 failed**.
- **`artifacts/run_all.json` и `docs/status.md`** (15:06) содержат устаревшее «655 passed, 1 skipped».
- **DEVLOG 21:12:** «аудит 92 418 записей, chain ok = true (21 685 + 70 731)» — в `soak_6h_2026-11-13.json` нет ни счётчика аудита, ни `chain ok`; сумма 92 416 ≠ 92 418 (2 записи не объяснены). «Success без артефакта».
- **Иммутабельный гейт тавтологичен** (см. п.4) — при ослаблении assert'ов правка констант пройдёт незамеченной.
- **`WIN-SERVICE-CREATE-007`:** заголовок «creation», match = regex `(?i)service` → ловит и `service_change`, и `service_state`; прогон ревьюера: `service_state` → high, confidence 1.0, `actions=('suspend',)`. Штатный старт службы может дать предложение suspend.
- **Структурно подозрительны:** `NET-EXFIL-LARGE-017` (>10 МБ без платформы, high, prevent), `FILE-MASS-WRITE-014` (50 записей/10 с → critical quarantine+suspend), `WIN-DOWNLOADS-EXEC-016` требует `integrity.verified=false`, а коллектор integrity не заполняет → недостижимо; `WIN-RUNKEY-005`/`SCHTASK-006`/`WMI-018` и process.*/memory.access недостижимы с категориями `winsource`.
- **Демон без коллекторов:** `DaemonConfig.sources = ["win.etw.ti","win.amsi"]` — реализаций нет; единственный реальный сборщик `core/winsource.py` инстанцируется только скриптами; `ResponseExecutor`/quarantine не подключены (`response_quarantine = None`). Цифры получены харнессами через `daemon.submit()`, а не продуктом.
- **IPC-дефект:** не-dict кадр 2 МиБ → `request.get("id")` на не-dict → `AttributeError` в потоке клиента, соединение рвётся, JSON-RPC ошибки нет; accept-loop выживает. Размер проверяется после полной десериализации — лимит не защищает память.
- **Гигиена:** 47 tracked-изменённых + 33 untracked; release baseline `e39a50a` отстаёт от кода; `docs/status.md` содержит NUL-байт (offset 1340, `stderr=\0`).

## Не удалось проверить

- `run_all` 29/29 — запрещён условием (перезаписывает `docs/status.md`); `run_all.json` от 15:06 уже устарел.
- 24-часовой soak / R1–R4 — только partial (`1744,2 с` на момент чтения), задача Running.
- E1–E6 / E7 / E9 — нет red-team/holdout, только авторские фикстуры.
- WDAC audit активация / 3076-3077 — нужна подписанная политика или VM без Secure Boot.
- ETW-TI / T1055 — admin есть, но `logman` → 0x80070005 (PPL); без драйвера не измерить.
- Драйвер/minifilter/eBPF-verifier, BSOD, фаззинг, `cargo-mutants`/clippy — нет VM/ядра.
- Долгий прогон на 3.14 — не выполнялся (только тесты).

## Топ-3 риска

1. **Числа «зелёного» прогона не воспроизводятся:** 656 → 661, а на 3.14 тест красный; `run_all.json`/`status.md` это маскируют. Это класс «success без повторного измерения».
2. **Immutable-гейт проверяет сам себя:** `verify_immutable()` — снимок против себя, `run_all` без эталона; при ослаблении assert'ов правка констант пройдёт незамеченной — а именно они держат fail-safe и запрет обучения на устройстве.
3. **Продуктовый путь не собран:** у демона нет коллекторов, response/ModelPack не подключены; `WIN-SERVICE-CREATE-007` превращает штатный `service_state` в high+suspend. «Измеренные» цифры — про харнессы, не про работающий агент.

## Ограничения независимости

Модель — `deepseek-flash` (та же семья, что автор `deepseek-v4-pro`), формально `reviewer_model != author_model`, но вендор один. Рабочая директория была живой: параллельный процесс создал `docs/reviews/` (22:47:55) и перезаписал `artifacts/docs_consistency.json` (22:49:35), soak-харнесс обновляет partial-артефакты. Код не менялся; вывод писался только в temp. **Вердикт — дополнительный гейт, не замена human-review уровня C.**
