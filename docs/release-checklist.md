# Release checklist

> Статус на 2026-11-13: **не готово к production**. Чек-лист фиксирует, что
> уже закрыто, что осталось и кто владелец.

## 1. Код и контракты

- [x] User-mode ядро, 28 правил, 21 схема, тесты Python (624 passed / 1 skip на момент F11).
- [x] Rust-порт 12 модулей: 133 теста, gate, benchmark, Python-wire IPC.
- [x] Immutable-константы не менялись; fingerprint стабилен.
- [x] `secrets/` исключён из git; dev-ключ не production.
- [ ] Пакетная поставка `rules/` и `models/` вне checkout.
- [ ] Полный `pip install` + запуск демона в чистом окружении (сейчас проверяется только editable-install).
- [ ] Windows service / systemd unit / installer (MSI/deb/rpm) — **не сделано**.

## 2. Надёжность

- [ ] R1/R4: 24-часовой soak без `0xC0000005`; сейчас F11 открыт (2 падения из 2).
- [ ] 7-дневный soak на always-on VM.
- [x] R2/R3/R6/R8/R9/R10 измерены (см. `artifacts/stage1_report.json`).
- [ ] R7 (FP-отключения) — нужен пилот.

## 3. Эффективность

- [ ] E7 ≥0,95 @0,05 % FPR (сейчас 0,6724).
- [ ] E12 <0,1 % в enforce (сейчас 13,3 % audit).
- [ ] E1–E6/E8 — red-team 20 сценариев/ОС и 7-дневный пилот.
- [x] E9 рабочая точка 56,4 % @0,05 % FPR; E10 в цели.
- [x] E11 28/28 на авторских фикстурах (не red-team).

## 4. Платформа и подпись

- [ ] A: EV-сертификат + Hardware Dev Center.
- [ ] B: Windows VM + WDK/testsigning.
- [ ] C: Linux VM + Secure Boot/fapolicyd/IMA.
- [ ] D: окно admin для WDAC enforce/ETW-TI/Windows T1055.
- [ ] Драйвер/minifilter/ELAM/WFP — не начаты.

## 5. Процесс

- [ ] Независимый auto-review (вторая модель, temperature=0); M8/M9.
- [ ] `human_acceptance` для релиза.
- [ ] Red-team и chaos перед релизом.
- [x] DEVLOG ведётся; измерения сопровождаются артефактами.
- [ ] `docs/status.md` без NUL; `dev-report`/`compliance-table` перегенерированы.

## 6. Инфраструктура

- [x] `.gitignore`, README, LICENSE (proprietary placeholder), SECURITY, CHANGELOG.
- [x] `pyproject.toml` с build-system и extras.
- [x] CI workflow (Windows: pytest + Rust test/clippy) — файл добавлен, но CI-раннер ещё не подключён.
- [ ] Lockfile/полный набор версий для production; текущий `requirements.lock` — снимок dev-среды.
- [ ] Подпись артефактов/репозитория обновлений.
- [ ] Резервное копирование/откат на уровне поставки.

## 7. Команды приёмки

```powershell
python -m pytest
python scripts\run_all.py
.\rust\gate.ps1
python scripts\docs_consistency.py
```

Критерий: все обязательные шаги зелёные, `docs_consistency` 15/15,
`docs/status.md` — валидный UTF-8 без NUL.
