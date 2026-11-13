# Промпт для независимого ревью в OpenCode (GLM-5.3-Flash)

> **Назначение:** внешняя независимая проверка готовности проекта.
> **Изоляция:** другая модель/вендор (`glm-5.3-flash` ≠ автор `deepseek-v4-pro`), свежий контекст, без доступа к рассуждениям автора — это удовлетворяет `reviewer_model != author_model` в терминах `docs/auto-reviewer-spec.md` §3.
> **Ограничение:** это **не** human-подпись для уровня C (драйвер/ядро/политика).

## Как запустить

1. Открыть в OpenCode папку проекта `D:\ИИ защитник Вектор-защитник`.
2. Выбрать модель **GLM-5.3-Flash** (или другую ≠ DeepSeek: MiniMax M3.1 Flash, LongCat 2.5, Nemotron 3.5 Super VL).
3. Вставить промпт ниже целиком.
4. Сохранить ответ в `docs/reviews/opencode-glm-5.3-<дата>.md`.
5. Записать результат в `DEVLOG.md` как `auto_review` (шаблон — в конце файла).

---

## ПРОМПТ (копировать целиком)

```
Ты — независимый ревьюер кода проекта «ИИ-защитник» (Windows/Linux EDR-прототип).
Ты не автор. Его рассуждений ты не видел и не должен им доверять.
Рабочая директория: D:\ИИ защитник Вектор-защитник

ЦЕЛЬ: независимо проверить готовность проекта по чек-листу и вернуть
структурированный вердикт. РЕЖИМ: только чтение и прогоны; код НЕ менять.

ШАГ 0 — прочитай:
1. docs/readiness-assessment.md
2. docs/auto-reviewer-spec.md
3. docs/status.md (генерируемый — только читать)
4. DEVLOG.md — выборочно, для сверки

ПРОВЕРКИ (выполни сам, фиксируй точные числа; зависимости уже установлены):
1. `python -m pytest -o addopts="" -q` — заявлено 655 passed / 1 skipped, но это может быть устаревшим. Запиши фактическое число и сверь с `docs/status.md` и `artifacts/run_all.json`. Уже найден дрейф: факт 661 passed / 0 skipped.
2. `cargo test --manifest-path rust/Cargo.toml` — ожидается 133 passed.
3. `python scripts/docs_consistency.py` — ожидается 13/13 (строгий набор; все проверки реальные, пропуск источника = fail).
4. Immutable: `python -c "from core.policy import verify_immutable; print(verify_immutable())"`
   — ожидается None; fingerprint d8ae913401ea…; core/policy.py не изменён.
5. `python scripts/export_schemas.py` — идемпотентен; committed JSON = генерация
   (drift-guard тест зелёный).
6. Выборочно (5–10) сверь записи DEVLOG с artifacts/*.json: под каждым «success»
   должно быть число/артефакт; отметь записи без измерения.
7. ML: ModelPack fail-closed (tampered → отказ, unsigned → отказ, чужой ключ →
   отказ); нет `fit`/`train` в runtime; ML в shadow (`actions_taken=0`).
8. Fail-safe: таймаут подтверждения = отказ; `terminate` недоступен исполнителю;
   destructive без оператора = 0.
9. IPC: `viewer` → `kill_switch` = FORBIDDEN; запрос 2 МиБ отклоняется, сервер
   не падает.
10. Структурно просмотри `rules/base.json` (28 правил): у каждого фикстура/тест,
    `rule_lint` = 0. Глубокую семантику не проверяй, но отметь可疑ное.

ОГРАНИЧЕНИЯ:
- НЕ запускай `scripts/run_all.py` (он перегенерирует docs/status.md).
- НЕ меняй ни одного файла, кроме собственного отчёта в docs/reviews/.
- Если проверить нельзя без admin/VM/ядра — честно пиши «не удалось», не выдумывай.

ВЕРНИ СТРОГО:
- ВЕРДИКТ: approve | request_changes | escalate
  (escalate, если провален P0 или числа расходятся с заявленными).
- ПРОВЕРЕНО (с числами): …
- НЕ СОШЛОСЬ (что и на сколько): …
- НЕ УДАЛОСЬ ПРОВЕРИТЬ (и почему): …
- ТОП-3 РИСКА: …
- ЧЕСТНОЕ ЗАМЕЧАНИЕ О НЕЗАВИСИМОСТИ: какая модель, был ли доступ к контексту
  автора, что это ограничивает.

Сохрани ответ в docs/reviews/opencode-glm-5.3-2026-11-13.md.
```

---

## Шаблон записи в DEVLOG (после получения отчёта)

```
## [YYYY-MM-DD HH:MM] Внешнее ИИ-ревью (OpenCode/GLM-5.3-Flash) [auto_review]

**Вердикт**: approve | request_changes | escalate
**Reviewer_model**: glm-5.3-flash (Zhipu, внешний)
**Author_model**: deepseek-v4-pro
**Изоляция**: reviewer_model != author_model = да; свежий контекст = да; temperature = 0
**Проверено (числа)**: …
**Не сошлось**: …
**Не удалось проверить**: …
**Решение / следующий шаг**: …
**Статус**: verified | unverified
**Actor**: human (запуск) + external_ai (ревью)
**Run_id**: opencode-glm-YYYY-MM-DD
```

## Что это ревью НЕ заменяет

- Human-подпись для драйвера/ядра (уровень C).
- Red-team E1–E6.
- Runtime-проверку на реальных ОС/VM.
