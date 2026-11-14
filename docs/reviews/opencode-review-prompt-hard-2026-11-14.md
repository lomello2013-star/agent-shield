# Жёсткий P0-промпт для внешнего ревью — 2026-11-14

> **Цель проверки:** HEAD `61a8316`.
> **Заявленные числа:** pytest **467 passed**; cargo **133**; `run_all` **29/29**;
> `docs_consistency` **13/13**.
> **Модель:** обязательно другой вендор (Gemini / GLM-5.3 / MiniMax), не DeepSeek.
> **Режим:** read-only; меняется только файл отчёта.
> **Правило:** любое расхождение факта с заявленным → `escalate`.

## Как запустить

1. OpenCode → папка `D:\ИИ защитник Вектор-защитник`.
2. Модель: Gemini (или другой вендор, не DeepSeek).
3. Вставить промпт ниже целиком.
4. Сохранить ответ в `docs/reviews/opencode-hard-<модель>-<дата>.md`.
5. Записать в DEVLOG как `auto_review`.

---

## ПРОМПТ

```
Ты — независимый аудитор проекта «ИИ-защитник» (Windows/Linux EDR).
Автор — deepseek-v4-pro; его рассуждений ты не видел.
Рабочая директория: D:\ИИ защитник Вектор-защитник
Проверяемая точка: HEAD 61a8316.
Заявлено автором: pytest 467 passed; cargo 133; run_all 29/29; docs_consistency 13/13.

ЖЁСТКИЕ ПРАВИЛА:
1. Каждую проверку выполняй сам; приводи точную команду и фактический вывод.
2. docs/status.md и artifacts/run_all.json — не источник истины: они могли быть
   сгенерированы до HEAD. Сверяй со своим прогоном и с `git rev-parse HEAD`.
3. Любое расхождение факта с заявленным/ожидаемым → ВЕРДИКТ escalate, без исключений.
4. Если проверка невозможна (нет admin/VM/Sysmon) — пиши «не удалось» и причину;
   не выдумывай результат.
5. Не меняй файлы репозитория, кроме своего отчёта.
6. Не запускай scripts/run_all.py: он перегенерирует docs/status.md и артефакты.
   Для проверки полноты читай artifacts/run_all.json и отдельные шаги.
7. VM AIDF-Win11 (если доступна) — только для проверки службы; код в репозитории
   не менять.

ОБЯЗАТЕЛЬНЫЕ ПРОВЕРКИ (P0):
1. `python -m pytest -o addopts="" -q` → точное «N passed, M skipped/failed».
   Сверь N с docs/status.md и artifacts/run_all.json (ожидается 467).
   Если есть skip — назови тест и причину; 467 vs 466+1 — объясни.
2. `cargo test --manifest-path rust/Cargo.toml` → точное число (ожидается 133).
3. `python scripts/docs_consistency.py` → passed/failed (ожидается 13/13).
   Проверь по коду: нет ли константно-True; при отсутствии источника проверка
   падает (fail), а не исчезает; status/tests-step-ok сверяет ЧИСЛО passed,
   а не только флаг.
4. Immutable:
   - `python -c "from core.policy import verify_immutable, POLICY_FINGERPRINT; verify_immutable(); print(POLICY_FINGERPRINT)"`
   - убедись, что verify_immutable() читает внешний docs/policy-contract.json,
     а не сравнивает модуль с самим собой;
   - `git diff --stat core/policy.py docs/policy-contract.json`;
   - кросс-язычная сверка (tests/test_policy.py + rust/tests/policy.rs).
5. Дрейф схем: экспорт 21 JSON-схемы во временную папку + побайтовое сравнение;
   drift-guard тест.
6. ML ModelPack: fail-closed на tampered/unsigned/чужой ключ/public_key=None/
   правку metrics; в core/*.py и rust/src/*.rs нет fit/train; shadow_only.
7. Fail-safe: таймаут → reject; terminate refused; destructive без оператора
   queued; «призрак approve» не исполняется; отказ не оставляет процесс висеть.
8. IPC:
   - viewer→kill_switch = -32002;
   - 2 МиБ dict → сервер жив, соединение закрывается (клиент может получить
     BrokenPipe; JSON-RPC -32600 не гарантируется — лимит до десериализации);
   - НЕ-dict кадр → -32600 и НЕ AttributeError/обрыв;
   - authkey: сервис делает bytes.fromhex(AIDF_AUTHKEY), CLI — fromhex;
     при расхождении confirm недостижим — проверь.
9. Правила: 28 правил / 28 фикстур, lint=0; WIN-SERVICE-CREATE-007 НЕ матчит
   action="service_state" и матчит "service_create"/"service_change".
10. Демон/служба (scripts/aidf_service.py):
    - ResponseExecutor + QuarantineStore подключены (daemon.response=);
    - collect_interval_s > 0 (иначе коллекторы не стартуют);
    - AIDF_ADMIN_TOKEN гейтит IPC;
    - AIDF_SYSMON=1 + channel_exists("Microsoft-Windows-Sysmon/Operational");
      при отсутствии канала — sysmon_missing в audit, источник не добавляется.
11. Sysmon actor_pid:
    - Event 1 → category process.start, ProcessId (в т.ч. hex 0x...) → actor.pid;
    - адаптер win.sysmon существует (иначе записи уходят в карантин);
    - build_default_collectors создаёт win.sysmon;
    - правило WIN-EXEC-TEMP-001 срабатывает на C:\Temp\*.exe.
12. Изоляция коллекторов: сбой одного коллектора НЕ ослепляет остальные;
    per-collector try/except в collect_once; тест.
13. Confirmation-путь: pending содержит target=PID; confirm approve исполняет
    ровно один раз; reject/timeout не исполняет; ghost approve не исполняется;
    действие без цели → action_skipped + response.skipped.
14. `aidfctl --params-file`: читает JSON из файла; не-объект отвергается;
    тест; confirm через файл не зависит от кавычек PowerShell.
15. Документация опции Sysmon: docs/sysmon.md, scripts/setup_sysmon.ps1,
    ссылка в docs/operations.md; ветка sysmon_missing проверена unit/static,
    live — только если Sysmon удалён.
16. Гигиена: `git status --short` (только soak-артефакт); NUL/ESC в
    docs/status.md; baseline не старше HEAD.

ИЗВЕСТНЫЕ ОГРАНИЧЕНИЯ (проверь, что они задокументированы, и не считай их
«работает», если заявлено иначе; escalate — только при переоценке):
- Windows suspend по 7045 без Sysmon недостижим → action_skipped.
- Ветка sysmon_missing проверена unit/static, не вживую.
- IPC службы включается только при AIDF_ADMIN_TOKEN.
- ETW/4688-путь для actor_pid не реализован; Sysmon — opt-in.
- Symlink-тест детерминирован (mock `islink` без прав); ожидается 467 passed,
  0 skipped. Если увидел skip в `test_quarantine_rejects_symlink` — это дефект
  детерминизма, escalate.

ВЕРНИ СТРОГО:
- ВЕРДИКТ: approve | request_changes | escalate.
- ФАКТЫ (команда → вывод).
- РАСХОЖДЕНИЯ (ожидалось / факт / источник).
- НЕ УДАЛОСЬ (причина).
- ТОП-3 РИСКА.
- ИЗОЛЯЦИЯ: модель, вендор, был ли доступ к рассуждениям автора, что ограничивает.
```

---

## Шаблон записи в DEVLOG

```
## [YYYY-MM-DD HH:MM] Жёсткое внешнее ревью (OpenCode/<model>) [auto_review]
**Вердикт**: approve | request_changes | escalate
**Reviewer_model**: <model>; **Author_model**: deepseek-v4-pro
**Изоляция**: другой вендор = да/нет; свежий контекст = да
**Факты**: …
**Расхождения**: …
**Не удалось**: …
**Статус**: verified | unverified
**Run_id**: opencode-hard-YYYY-MM-DD
```
