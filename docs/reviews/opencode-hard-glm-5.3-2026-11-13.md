# Жёсткое независимое P0-ревью (OpenCode / GLM-5.3-Flash)

> **Дата:** 2026-11-13. **Базлайн:** коммит `9d877bb` (после `959dfdc` — «Fix review findings»).
> **Режим:** только чтение и прогоны. Код не менялся; создан только этот отчёт.
> Исключения раскрыты в §«Влияние на дерево».

---

## ВЕРДИКТ: escalate

Правило №3 промпта: любой факт ≠ заявленному → escalate. Расхождений несколько:
pytest-счётчик невоспроизводим в заявленной формулировке, `docs_consistency` = 14/15
(заявлено 15/15), пер-корневая разбивка WDAC в DEVLOG ≠ артефакту, и в «исправляющий»
коммит `959dfdc` попали **494 файла pytest-мусора как tracked**.

---

## ФАКТЫ (команда → вывод)

### 1. pytest — заявлено «451 passed» (status.md, run_all.json, DEVLOG 23:35)
Команда: `.venv314\Scripts\python.exe -m pytest -o addopts= -q --junitxml=…` (junit — потому
что в этой среде pytest не печатает финальную строку счётчика ни в одном из 4 прогонов;
junit — машинный источник).

Вывод: **tests=451, failures=1, errors=0, skipped=1** → **449 passed, 1 failed, 1 skipped**.
- FAIL: `tests.test_response::test_suspend_and_resume_real_process`
- SKIP: `tests.test_response::test_quarantine_rejects_symlink` (нет прав на symlink)

Сверка с заявленным: `docs/status.md` содержит «451 passed in 8.53s»; `artifacts/run_all.json`
(generated_at 2026-11-13T20:13Z = 23:13 локального) — «451 passed». **Заявленное «451 passed»
не воспроизводится на .venv314 без admin**: 1 провал + 1 skip. По DEVLOG автора провал
воспроизводится на 3.14-venv (venv-redirector), а «451 passed» achievable только на базовом
3.12.9 (suspend ok, согласно его же записи 22:45) — вероятно, под admin (тогда skip исчезает).
Итог: число зависит от окружения, в текущем — расходится. ❌

Дополнительно: заявленная в коммите «3.14 compat» **не подкреплена кодом** — `git log` по
`core/response.py` показывает отсутствие изменений с baseline `b124e59`; `ProcessController`
так и не разрешает redirector-потомка. Тест suspend падал у меня в 5/5 прогонов (4 — вчера, 1 — сегодня).

### 2. cargo test — ожидается 133
Команда: `cargo test --manifest-path rust\Cargo.toml`
Вывод: сумма по всем test-бинарям лога: **133 passed, 0 failed**. ✅

### 3. docs_consistency — заявлено 15/15
Команда: `.venv314\Scripts\python.exe scripts\docs_consistency.py`
Вывод: **passed 14, total 15** — `devlog/recent-fields` FAIL: свежая запись DEVLOG
«[2026-11-13 23:16] Уточнение… [report]» не содержит обязательных полей `**Вердикт` / `**Числа`
(формат `[report]` требует все пять полей; исключение в скрипте сделано только для
`[auto_review]`/`[escalation]`). ❌ расхождение с «15/15» (DEVLOG 23:35).

Независимость проверок: из 15 — **2 константно-True** (`devlog/field-coverage`,
`devlog/auto-review-disclosed`), несколько — условные: если артефакт-источник отсутствует
(`run_all.json`, `t1055_coverage.json`, `pe_v2_report.json`), проверка молча пропускается,
а не падает. `status/tests-step-ok` проверяет `ok=True` **предыдущего прогона** —
тавтологично по отношению к самому run_all (это честно оговорено в комментарии скрипта).

### 4. Immutable
- `python -c "from core.policy import verify_immutable…"` → **None**, fingerprint
  `d8ae913401ead8b0d549dbae9d0efb299020b24e49b87a9385ab7071446ea759` ✅
- Не тавтологично: `verify_immutable()` сравнивает live-константы с внешним tracked
  `docs/policy-contract.json` (constants + fingerprint), договор существует, fingerprint
  совпадает с `POLICY_FINGERPRINT`. ✅
- `git diff --stat core/policy.py docs/policy-contract.json` → пусто (не изменены). ✅
- Кросс-язычный тест: `tests/test_policy.py::test_policy_fingerprint_matches_rust_contract`
  существует; литерал `d8ae913401ea…` найден в `rust/tests/policy.rs`. ✅
- Отмечу остаточный риск: fingerprint считается **из самих констант модуля**; пара
  «константы + fingerprint» в contract.json — внешний файл, защищённый только git-историей.
  Для целей ревью — достаточно; для уровня C — human-подпись обязательна.

### 5. Дрейф схем
Команда: `python scripts/export_schemas.py` → `git diff` / `git diff --ignore-cr-at-eol`
Вывод: **21 файл**, diff **2046/2046 симметричных замен строк**; с `--ignore-cr-at-eol` —
пусто → семантического дрейфа нет, drift-guard тест зелёный. **Байт-идемпотентность не
починена** (каждый прогон переписывает все 21 файл CRLF↔LF; замечание из прошлого ревью
не устранено). ⚠️ (возвращено к коммиту `git checkout -- schemas/`)

### 6. DEVLOG ↔ артефакты — 10 сверок
| # | Запись (DEVLOG) | Артефакт | Число в записи | Число в артефакте | Итог |
|---|---|---|---|---|---|
| 1 | R2/R3 (final_summary) | stage1_report.json | 59,5 с / 110,5 мс | max_latency_s 59.5 / mttr_ms_p95 110.5 | ✅ |
| 2 | soak 35653 событий | soak_report.json (via docs_consistency) | 35653 | events_fed 35653 | ✅ |
| 3 | F11: «2 краша / 2 чистых» | f11_repeat.json | 4 раунда, 2 crash | rounds 4, crashes 2 | ✅ |
| 4 | ETW-TI «измерен отказ» | etwti_t1055.json | 0x80070005 | start.ok=false, rc 2147942405 | ✅ |
| 5 | WDAC FBR выборка 120 | wdac_audit.json | 6,67 % | fbr_pct 6.67 | ✅ |
| 6 | Аудит 1077 зап./с | stage11_report.json | 1077 / 21,886 мс | records_per_s 1077.0 / verify_ms 21.886 | ✅ |
| 7 | WDAC полный парк | wdac_inventory.json | 2414 / 1993 / 421 / 17,44 / 20,46 | идентично | ✅ |
| 8 | «15 612 записей аудита целы» | soak_supervised.json | 15612 | audit_chain.records 15612 | ✅ |
| 9 | cargo gate ok | rust_gate.json | fmt/clippy/test ok | ok:true, 3 шага | ✅ |
| 10 | WDAC пер-корневая разбивка (23:05) | wdac_inventory.json | **PF 672, PF(x86) 496** | **PF 824, PF(x86) 480** | ❌ |

Несошедшееся: №10 — сумма в записи (770+340+672+496=2278) ≠ сумме артефакта
(770+340+824+480=2414), хотя итог «2414» в записи совпадает с артефактом. Разбивка — неверна.

### 7. ML fail-closed
- `verify_pack(public_key=None)` → `VerificationResult(False, "untrusted_key")` (в коде и
  тесте `test_no_trusted_key_rejected`) ✅
- tampered artifact / tampered manifest / wrong key / unsigned / missing artifact — 10
  тестов `test_modelpack.py` зелёные ✅
- Правка `metrics` ломает подпись структурно (metrics входят в `canonical_payload`,
  подпись поверх) — **отдельного теста на metrics нет**, приёмка по коду, не по тесту ⚠️
- `fit/train/partial_fit`: grep по `core/*.py` и `rust/src/*.rs` → **0 совпадений** ✅
- shadow: `core/ml.py` — `reason_code="ml_shadow_score"`, `"shadow": True` ✅

### 8. Fail-safe — собственные runtime-пробы (не тесты автора)
- таймаут: `expire()` → decision **"reject"**, decided_by "timeout", `executable()=False` ✅
- «призрак approve»: approve ПОСЛЕ таймаута → `resolve()` возвращает decision "reject"
  (first decision wins), `executable()=False` ✅
- destructive без оператора → `queued=True`, decision "pending", `executable()=False`;
  после явного одобрения оператора исполняемо (это спроектированный путь «очередь → оператор») ✅
- terminate у исполнителя → **refused** («irreversible action requires human approval path») ✅

### 9. IPC — собственные runtime-пробы (реальный транспорт, не диспетчер)
- viewer → `kill_switch` → **-32002** «role 'viewer' may not call 'kill_switch'» ✅
- non-dict кадр `[1,2,3]` → **-32600** «request must be a JSON object», соединение живо
  (последующий ping по тому же кадру — ok) ✅
- 2 МиБ dict: лимит `recv_bytes(maxlength)` **до** `pickle.loads` (код `core/ipc.py`,
  «P0-5»); фактически клиент получает `BrokenPipeError` при попытке отправить 2 МиБ,
  сервер ветку `OSError → -32600 "request too large"` отрабатывает и **не падает** —
  последующие подключения работают. Примечание: клиентское переживание атаки грубее, чем
  «клиент получает -32600» (труба закрыта на 1 МиБ), но защитное свойство (сервер жив,
  oversized отклонён) выполняется. ✅ с оговоркой.

### 10. Правила
- `load_rules(['rules/base.json'])` → **28 правил**; `lint_rules()` → **0 problems** ✅
- Фикстуры: `tests/rules_cases.py` → `RULE_CASES` содержит ровно **28 ключей**, каждая —
  валидный id правила, без лишних ✅
- `WIN-SERVICE-CREATE-007`: match = `{"category": "persistence.change",
  "action": {"in": ["service_create","service_change"]}, "platform":"windows"}` — regex
  отсутствует. Проба через `rule_matches`: `service_create` → MATCH, `service_change` →
  MATCH, **`service_state` → no match**, отсутствие action → no match ✅ (исправлено с
  прошлого ревью; честная самокоррекция автора в записи 23:16)

### 11. Демон — коллекторы и response
`core/daemon.py`: `DaemonConfig.sources` (["win.etw.ti","win.amsi"]); конструктор принимает
`collectors=` и `response=`; `self.collectors`, `_start_collectors()` (фоновый опрос),
`collect_once()`; `response.quarantine` подключается (`response_quarantine`). Тест
`tests/test_daemon_wiring.py` (4 теста) зелёный. ✅ по коду.
Открытые пункты (признаёт сам автор в 23:35): реальные wevtutil-коллекторы в демон ещё
не включались (проверка на фейковом коллекторе); QA процесса «событие → вердикт → действие»
на реальном источнике не доказано.

### 12. Гигиена
- `git status --short` → **1 изменённый**: `artifacts/soak_supervised_partial.json` —
  его мутирует **живой** scheduled soak (`AIDF-Soak24`, AtStartup): baseline буквально
  «дышит» во время ревью.
- NUL в `docs/status.md`: `b"\x00" in raw` → **False** ✅ (ранее читался как binary —
  причина была в другом чтении; сейчас чисто).
- **Критичное**: коммит `959dfdc` закоммитил **494 файла** `pytest-of-lomel/pytest-{6,7,8}/**`
  (tracked временные артефакты pytest). Следствия: любой прогон тестов меняет tracked-файлы
  (сотни D/M в git status), «зелёное» состояние дерева невоспроизводимо, diff-шум маскирует
  реальные изменения. Это сделано в том же коммите, где заявлено «git status → 0 изменений». ❌
- `rust_gate.json` сохранён с UTF-8 BOM (загружается только `utf-8-sig`) — мелочь, но
  та же болезнь, что лечил `strip_bom.py`.

## РАСХОЖДЕНИЯ (ожидало → факт → источник)
1. «451 passed» (status.md, run_all.json, DEVLOG 23:35) → **449 passed / 1 failed / 1 skipped**
   на .venv314 → провал воспроизводим, заявленная формулировка — только на
   base-3.12.9+admin. P0-гейт зависит от окружения.
2. «docs_consistency 15/15» (DEVLOG 23:35) → **14/15** (свежая запись 23:16 ломает поле-чек).
3. WDAC per-root 672/496 (DEVLOG 23:05) → **824/480** (артефакт).
4. «3.14 compat» (название коммита 959dfdc) → код `ProcessController` не менялся; тест
   suspend падает 5/5 на 3.14-venv. Формулировка коммита вводит в заблуждение.
5. «stable test count» (959dfdc) → достигнут, но одновременно закоммичены 494 файла
   pytest-мусора — «стабильность» куплена ценой трекинга временных артефактов.

## НЕ УДАЛОСЬ
- Воспроизвести «451 passed» в моём окружении (нет admin-окна; suspend-тест требует
  base-интерпретатора) — причина: environment, не код.
- Проверить `run_all.py` 29/29 вживую — запрещено промптом (перегенерирует status.md).
- temperature=0 — недоступно для проверки изнутри сессии.
- Реальные collectors (wevtutil) в демоне, RTP, WDAC enforce, ETW-TI события, T1055 на
  Windows — нужны admin/VM/перезагрузка (и сам автор это фиксирует).
- Мутационное тестирование / сев-дефекты / построчный coverage — вне объёма промпта.

## ТОП-3 РИСКА
1. **Test-junk в VCS**: 494 tracked файла `pytest-of-lomel` — каждый прогон тестов
   «портит» дерево; git-состояние перестаёт быть надёжным свидетельством (P2-гигиена,
   раненная до уровня P0, потому что ломает саму верифицируемость).
2. **Suspend-дефект не исправлен, а «3.14 compat» заявлен**: на любом venv-хосте
   EDR-действие «suspend по pid» молча не останавливает реальный процесс — это
   продуктовый пробел, замаскированный формулировкой коммита.
3. **Заявления привязаны к окружению автора**: «451 passed», «git status 0», «15/15» —
   верны в его сессии (admin, base-python, момент до записи 23:16 и до мутации soak),
   но не воспроизводимы извне. Гейт P0 должен зависеть от кода, а не от сессии.

## ИЗОЛЯЦИЯ
- **Модель/вендор:** GLM-5.3-Flash (Zhipu) ≠ deepseek-v4-pro (DeepSeek) — вендоры разные ✅
- **Свежий контекст:** да; сессия не является fork'ом сессии автора; к его рассуждениям
  доступа не было. Читал его документы и DEVLOG по методике аудита («документ ↔ факт»),
  все числа — из собственных прогонов и чтения кода/артефактов.
- **temperature:** подтвердить не могу → формальное условие spec §3 остаётся неподтверждённым;
  сам по себе это не escalate-триггер, но лишает вердикт статуса «полностью валидного» по spec.
- **Границы:** не заменяет human-подпись уровня C, red-team E1–E6, проверку на реальных ОС/VM.

## Влияние на дерево (раскрытие)
- Создан только `docs/reviews/opencode-hard-glm-5.3-2026-11-13.md`.
- `docs_consistency.py` и `export_schemas.py` перезаписали tracked артефакты во время
  проверки — оба возвращены к коммиту (`git checkout`), семантических изменений нет.
- `pytest-of-lomel/` — tracked-мусор, попавший в `959dfdc`: я удалил его при уборке и
  **восстановил как было** (`git checkout -- pytest-of-lomel`); дерево оставлено в
  найденном состоянии. Сам факт трекинга — находка для владельца.
- Итоговое состояние после ревью: `git status --short` = 1 файл
  (`artifacts/soak_supervised_partial.json`, мутируется живым soak-заданием — не мною).

## Рекомендации (порядок)
1. Удалить `pytest-of-lomel/` из VCS (`git rm -r --cached`) + вынести basetemp pytest
   за пределы репозитория; закоммитить `.gitignore`.
2. Исправить `ProcessController.suspend` (redirector-потомок) или честно переформулировать
   «3.14 compat»; suspend-тест пометить `xfail` с reason до исправления.
3. Починить `devlog/recent-fields` для записи 23:16 (добавить `**Вердикт`/`**Числа`) —
   вернёт 15/15; сделать условные проверки docs_consistency «fail loudly» при
   отсутствии артефакта-источника.
4. Сверить/исправить пер-корневую разбивку в DEVLOG 23:05.
5. Байт-идемпотентность `export_schemas.py` (CRLF) — из прошлого ревью, всё ещё открыт.
6. После 1–5: перегенерировать status/run_all на зафиксированном baseline и повторный
   P0-прогон → тогда возможен `approve`/`request_changes`.
