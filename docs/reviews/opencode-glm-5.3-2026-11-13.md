# Независимое ИИ-ревью (OpenCode / GLM-5.3-Flash)

> **Дата:** 2026-11-13. **Ревьюер:** glm-5.3-flash (Zhipu), внешний запуск через OpenCode.
> **Режим:** только чтение и прогоны; код не менялся (исключение см. §«Влияние ревьюера на рабочее дерево»).
> **Чек-лист:** `docs/readiness-assessment.md` §5 (P0), `docs/auto-reviewer-spec.md` §3–4.

---

## ВЕРДИКТ: escalate

Основания (по критериям промпта и spec §3/§10):

1. **Числа расходятся с заявленными.** Заявлено P0: «655 passed, 1 skipped». Измерено ревьюером:
   **661 collected = 659 passed, 1 failed, 1 skipped** (`.venv314`, Windows, junit-отчёт).
   Расхождение частично объяснимо (см. ниже), но по правилу «любое расхождение — разобрать»
   и «escalate, если числа расходятся» — эскалация.
2. **1 проваленный тест** в полном прогоне: `tests/test_response.py::test_suspend_and_resume_real_process`
   (воспроизведён 4/4 прогонов). Причина задокументирована автором (DEVLOG 22:45, «venv-redirector»),
   но факт провала не совпадает с формулировкой P0-чек-листа «1 skipped».
3. **Изоляция формально неполная:** `temperature` этой сессии недоступен мне для проверки —
   условие `reviewer_temperature == 0` (spec §3) не подтверждено → по spec §3 вердикт не может
   быть `approve`.

---

## ПРОВЕРЕНО (с числами)

| # | Проверка | Заявлено | Измерено ревьюером | Итог |
|---|---|---|---|---|
| 1 | `python -m pytest -q` | 655 passed, 1 skipped | **661 collected: 659 passed, 1 failed, 1 skipped**, 30,7 с (junit). Провал: `test_suspend_and_resume_real_process`; skip: `test_quarantine_rejects_symlink` (нужны права на symlink) | ❌ расхождение |
| 2 | `cargo test --manifest-path rust/Cargo.toml` | 133 passed | **133 passed, 0 failed** (сумма по всем test-бинарям лога) | ✅ |
| 3 | `python scripts/docs_consistency.py` | 15/15 | **passed 15, total 15, failed []** | ✅ |
| 4 | `verify_immutable()` | None; fp `d8ae913401ea…` | **None**; `POLICY_FINGERPRINT = d8ae913401ead8b0…ea759` (sha256 immutable-констант, т.е. «fingerprint политики», не файла — формулировка промпта двусмысленна, но значение совпало). `git status core/`: `policy.py` чист | ✅ |
| 5 | `export_schemas.py` идемпотентен | committed JSON = генерация | Семантически идемпотентен, **но не байт-в-байт**: регенерация переписывает все 21 файл переводами строк (CRLF↔LF) — `git diff` даёт 2046/2046 симметричных замен строк; `git diff --ignore-cr-at-eol` пуст. Drift-guard это пропускает (сравнивает JSON, не байты) | ⚠️ условно |
| 6 | DEVLOG ↔ артефакты (6 выборок) | нет «success без числа» | `stage1_report.json` (59,5 с; MTTR 110,5 мс), `soak_6h_2026-11-13.json` (window 21640 с, 0 рестартов, 100 %), `f11_repeat.json` (4 раунда, **2 краша 0xC0000005** — честно отражено в README), `etwti_t1055.json` (`start.ok=false`, 0x80070005 — заголовок записи «ETW-TI измерен и закрыт» звучит как успех, но тело честно фиксирует отказ), `wdac_audit.json` (120 выборка, FBR 6,67 %), `stage11_report.json` (1077 зап./с, verify 21,886 мс) | ✅ сходится |
| 7 | ML fail-closed / нет train / shadow | fail-closed; shadow | В `core/` **нет** `.fit(`/`.train(`/`partial_fit` (grep). `core/ml.py` — только shadow (`reason_code="ml_shadow_score"`, `"shadow": True`). `test_modelpack.py`: 10 тестов — tampered manifest/artifact, unsigned, wrong key, missing artifact, no trusted key — **все зелёные** | ✅ |
| 8 | Fail-safe | таймаут = reject; terminate недоступен; destructive без оператора = 0 | `FAIL_SAFE_ON_TIMEOUT = "reject"` (immutable); `core/confirm.py`: «timeouts never approve»; `test_executor_refuses_terminate` → `refused`; `stage1_report.json`: «reject 100/100, destructive 0» | ✅ |
| 9 | IPC роли / oversized | viewer→kill_switch FORBIDDEN; 2 МиБ отклоняется | `RpcRegistry`: `kill_switch` только для `admin`; `MAX_MESSAGE = 1 МиБ`, запрос > лимита → «request too large» (2 МиБ тем более отклоняется); `test_viewer_cannot_call_admin_method` зелёный | ✅ |
| 10 | `rules/base.json` | 28 правил, lint 0 | **28 правил**, lint_rules → **0 problems**; lint реально проверяет дубликаты/regex/window/techniques (tests/test_rules.py, test_rules_correlation.py). Глубокая семантика не проверялась | ✅ |
| — | cargo gate (fmt+clippy) | см. README | Не запускал отдельно; заявленные `artifacts/rust_gate.json` не перепроверял построчно | — |

## НЕ СОШЛОСЬ

1. **Счёт тестов.** Заявлено 655+1=656 прогонов. В рабочем дереве собрано **661**.
   Разбор: в дереве есть **незакоммиченные** изменения — `tests/test_daemon.py` (+1 тест,
   lifecycle-записи) и **untracked** `tests/test_supervisor.py` (+7 тестов) → +8 к коммиту.
   661 − 8 = 653 по коммиту — против заявленных 656 остаётся **3 необъяснённых теста**
   (возможно, на хосте автора symlink-тест выполнялся под admin и не скипался; требует уточнения автором).
2. **`test_suspend_and_resume_real_process` падает 4/4** на `.venv314` (venv-redirector 3.14:
   pid заглушки ≠ pid реального интерпретатора-потомка; `NtSuspendProcess` по заглушке не
   останавливает работу). Автор это знает и задокументировал (DEVLOG 22:45, «известное
   расхождение»), но: а) P0-формулировка «655 passed, 1 skipped» противоречит собственной
   записи автора «655 passed, **1 failed**»; б) дефект `ProcessController.suspend`
   (не разрешает redirector-потомка) — реальный пробел продукта для любого venv-хоста.
3. **`docs/status.md` нечитаем инструментами ревьюера** (read как «binary»): файл в UTF-8
   без BOM, но с содержимым, которое ломает некоторые пайплайны — для «генерируемого»
   артефакта стоит зафиксировать кодировку/тип в README-таблице. Мелочь, но она усложнила проверку.

## НЕ УДАЛОСЬ ПРОВЕРИТЬ

- **`run_all.py` 29/29** — запрещено промптом (перегенерирует `docs/status.md`). Заявленные
  «655 passed» в `artifacts/run_all.json` не воспроизводятся в текущем дереве (см. выше).
- **temperature=0** — недоступно для проверки изнутри сессии.
- **Глубокая семантика 28 правил** (ловит ли правило технику, а не строку) — вне объёма;
  отмечено как требующее human-review.
- **Windows-runtime** (RTP, WDAC enforce, ETW-TI события, T1055) — нужны admin/перезагрузка/VM;
  по артефактам: ETW-TI = отказ 0x80070005, enforce не развёрнут, RTP ждёт ребута — ревьюеру проверить нечем.
- **Мутационное тестирование, сев-дефекты, coverage ≥80 % построчно** — не запускалось
  (вне чек-листа промпта; spec §4.5/§4.7/§4.8 требует для полного вердикта уровня B).

## ТОП-3 РИСКА

1. **Вердикт выносится по «движущейся цели».** В рабочем дереве незакоммичены: `core/daemon.py`
   (+lifecycle-аудит), `core/supervisor.py` (untracked — **runtime-модуль вне VCS**!),
   `tests/test_supervisor.py`, DEVLOG и ~30 артефактов. Любое «зелёное» состояние невоспроизводимо:
   сегодня 661, после коммита будет 653, заявлено 656. До коммита baseline ревью и релиз невозможны.
2. **`ProcessController.suspend` по pid не покрывает redirector-потомка** — на 3.14-venv (и любых
   будущих топологиях «заглушка → потомок») EDR-действие молча не останавливает реальный процесс.
   Это не только тест, это продукт: пользователь, запустивший защиту из venv, получает
   suspend «в никуда» без ошибки.
3. **Байт-недетерминизм `export_schemas.py`** (CRLF) — каждый прогон пачкает дифф всех 21 схемы;
   реальный drift потеряется в шуме. Фикс: писать байты как в коммит или нормализовать окончания.

## ЧЕСТНОЕ ЗАМЕЧАНИЕ О НЕЗАВИСИМОСТИ

- **Модель:** glm-5.3-flash (Zhipu), запуск через OpenCode, свежий контекст, сессия не является
  fork'ом сессии автора. `reviewer_model ≠ author_model` (glm-5.3-flash ≠ deepseek-v4-pro) — подтверждено.
- **Доступ к контексту автора:** к рассуждениям/диалогу автора доступа не было. Однако я
  **читал авторские документы** (readiness-assessment, auto-reviewer-spec, DEVLOG, артефакты) —
  это предусмотрено методикой (проверка «документ ↔ реальность»), но вводит риск якорения
  на авторские формулировки; списки «ПРОВЕРЕНО» построены на собственных прогонах, не на доверии.
- **temperature:** мне недоступна — формальное условие spec §3 не подтверждено; я обязан
  трактовать изоляцию как неполную.
- **Границы:** это ревью **не заменяет** human-подпись уровня C (драйвер/ядро/политика),
  red-team E1–E6 и runtime-проверку на реальных ОС/VM (spec §6.3, readiness §6.3).

## Влияние ревьюера на рабочее дерево (раскрытие)

- Создан только этот отчёт: `docs/reviews/opencode-glm-5.3-2026-11-13.md`.
- `export_schemas.py` (проверка №5) переписал 21 схему переводами строк — возвращено к
  коммиту (`git checkout -- schemas/`), семантической потери нет (дифф был только CRLF/LF).
- Побочные эффекты прогонов pytest/cargo: стандартные кэш/артефакты инструментов
  (`.pytest_cache`, `rust/target/test-tmp`, `pytest-of-lomel`) — не в git, как и до ревью.
- `scripts/run_all.py` не запускался; `docs/status.md`, DEVLOG, код — не изменены.

## Рекомендация по снятию эскалации

1. Закоммитить baseline (core/supervisor.py, daemon lifecycle, тесты, DEVLOG, артефакты) —
   одно состояние = один вердикт.
2. Уточнить у автора происхождение «655/656» против коммит-коллекции 653 (или пересчитать claim).
3. Исправить `ProcessController.suspend` (разрешение redirector-потомка) + тест, закрывающий кейс.
4. Сделать `export_schemas.py` байт-идемпотентным; drift-guard — по байтам.
5. Повторный прогон P0 на зафиксированном baseline → тогда `approve`/`request_changes` становится возможным.
