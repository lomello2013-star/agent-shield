# Жёсткий P0-промпт для внешнего ревью

> **Модель:** обязательно ≠ DeepSeek (GLM-5.3-Flash / MiniMax M3.1 / LongCat 2.5). Иначе изоляция слабая.
> **Режим:** read-only, код не менять.
> **Правило:** любое расхождение факта с заявленным → `escalate`. «Выглядит нормально» не принимается.

## Как запустить

1. OpenCode → папка `D:\ИИ защитник Вектор-защитник`.
2. Модель: GLM-5.3-Flash (или другой вендор).
3. Вставить промпт ниже целиком.
4. Сохранить ответ в `docs/reviews/opencode-hard-<модель>-<дата>.md`.
5. Записать в DEVLOG как `auto_review` (вердикт + числа).

---

## ПРОМПТ

```
Ты — аудитор проекта «ИИ-защитник». Ты не автор, его рассуждений не видел.
Рабочая директория: D:\ИИ защитник Вектор-защитник

ЖЁСТКИЕ ПРАВИЛА:
1. Каждую проверку выполняй сам; приводи точную команду и фактический вывод (число).
2. Не доверяй docs/status.md и artifacts/run_all.json — они могли быть сгенерированы
   до изменений. Сверяйся со своим прогоном.
3. Если факт ≠ ожидаемому или ≠ заявленному в docs/status.md → ВЕРДИКТ escalate,
   без исключений.
4. Если проверка невозможна (нет admin/VM/ядра) — пиши «не удалось» и причину;
   не выдумывай.
5. Не меняй ни одного файла, кроме своего отчёта.
6. Не запускай scripts/run_all.py (он перегенерирует docs/status.md).

ОБЯЗАТЕЛЬНЫЕ ПРОВЕРКИ (P0):
1. `python -m pytest -o addopts="" -q` → точное «N passed, M skipped/failed».
   Сверь N с docs/status.md и artifacts/run_all.json.
2. `cargo test --manifest-path rust/Cargo.toml` → точное число (ожидается 133).
3. `python scripts/docs_consistency.py` → passed/failed; отметь, сколько проверок
   константно-True (независимые ли это проверки).
4. Immutable:
   - `python -c "from core.policy import verify_immutable, POLICY_FINGERPRINT; verify_immutable(); print(POLICY_FINGERPRINT)"`
   - проверь, что verify_immutable() сравнивает с docs/policy-contract.json,
     а не со snapshot() (не тавтологичен);
   - `git diff --stat core/policy.py docs/policy-contract.json`;
   - проверь кросс-язычную сверку tests/test_policy.py::test_policy_fingerprint_matches_rust.
5. Дрейф схем: `python scripts/export_schemas.py` в temp + сравнение 21 файла;
   drift-guard тест.
6. DEVLOG↔артефакты: 10 сверок, каждая «запись → артефакт → число»;
   перечисли несошедшиеся.
7. ML: ModelPack fail-closed (tampered/unsigned/чужой ключ/public_key=None/
   правка metrics), нет fit/train в core/*.py и rust/src/*.rs, shadow_only.
8. Fail-safe: таймаут→reject; terminate refused; destructive без оператора queued;
   «призрак approve» не исполняется.
9. IPC: viewer→kill_switch = -32002; 2 МиБ dict → **сервер жив**, соединение
   закрывается (клиент может получить BrokenPipe; JSON-RPC -32600 не
   гарантируется — лимит срабатывает до десериализации); НЕ-dict кадр → -32600
   и НЕ AttributeError/обрыв.
10. Правила: 28 правил, 28 фикстур, lint=0; WIN-SERVICE-CREATE-007 НЕ матчит
    action="service_state" и матчит "service_create"/"service_change".
11. Демон: DaemonConfig.sources — реализованы ли коллекторы? подключены ли
    ResponseExecutor/quarantine? Если нет — зафиксируй как открытый пункт.
12. Гигиена: `git status --short` (счётчик); NUL в docs/status.md
    (`b"\x00" in open("docs/status.md","rb").read()`); актуальность baseline.

ВЕРНИ СТРОГО:
- ВЕРДИКТ: approve | request_changes | escalate (escalate при любом расхождении).
- ФАКТЫ (команда → вывод).
- РАСХОЖДЕНИЯ (ожидалось / факт / источник).
- НЕ УДАЛОСЬ (причина).
- ТОП-3 РИСКА.
- ИЗОЛЯЦИЯ: модель, вендор, был ли доступ к рассуждениям автора, что это ограничивает.
```

---

## Шаблон записи в DEVLOG

```
## [YYYY-MM-DD HH:MM] Жёсткое внешнее ревью (OpenCode/<model>) [auto_review]
**Вердикт**: approve | request_changes | escalate
**Reviewer_model**: <model>; **Author_model**: deepseek-v4-pro
**Изоляция**: другой вендор = да/нет; свежий контекст = да; temperature = 0
**Факты**: …
**Расхождения**: …
**Не удалось**: …
**Статус**: verified | unverified
**Run_id**: opencode-hard-YYYY-MM-DD
```
