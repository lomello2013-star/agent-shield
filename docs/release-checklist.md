# Release checklist

> Статус на 2026-11-13 (вечер): **не готово к production**. Чек-лист фиксирует, что
> уже закрыто, что осталось и кто владелец.

## 1. Код и контракты

- [x] User-mode ядро, 28 правил, 21 схема, тесты Python (**533 passed / 0 skip**, включает STML; `run_all` 29/29).
- [x] Rust-порт 12 модулей: 133 теста, gate, benchmark, Python-wire IPC.
- [x] Immutable-константы не менялись; fingerprint стабилен.
- [x] `secrets/` исключён из git; dev-ключ не production.
- [x] **Windows-служба `AIDefender`** установлена (ctypes SCM-хост, автозапуск, start/stop ~0,3 с).
- [ ] Пакетная поставка `rules/` и `models/` вне checkout.
- [ ] Полный `pip install` + запуск демона в чистом окружении (сейчас проверяется только editable-install).
- [ ] Installer (MSI/deb/rpm) и systemd unit для Linux — **не сделано**.

## 2. Надёжность

- [ ] R1/R4: 24-часовой soak без `0xC0000005`. Прогон идёт под супервизором; после обновления CPython 3.12.9 — **6 ч и 38 мин без падений** (лучший результат), сутки ещё не набраны.
- [ ] 7-дневный soak на always-on VM.
- [x] R2/R3/R6/R8/R9/R10 измерены (см. `artifacts/stage1_report.json`); R3 дополнен супервизором (перезапуск ~0,28 с).
- [ ] R7 (FP-отключения) — нужен пилот.

## 3. Эффективность

- [ ] E7 ≥0,95 @0,05 % FPR (сейчас 0,6724 — потолок статики подтверждён тремя приёмами).
- [ ] E12 <0,1 % в enforce (сейчас 13,3 % на held-out; enforce не развёрнут).
- [ ] E1–E6/E8 — red-team 20 сценариев/ОС и 7-дневный пилот.
- [x] E9 рабочая точка 56,4 % @0,05 % FPR; E10 в цели.
- [x] E11 28/28 на авторских фикстурах (не red-team).

## 4. Платформа и подпись

- [ ] A: EV-сертификат + Hardware Dev Center (нужен и для подписи драйвера, и для подписи CI-политики).
- [ ] B: Windows VM + WDK/testsigning — единственный безопасный путь проверить WDAC enforce.
- [ ] C: Linux VM + Secure Boot/fapolicyd/IMA.
- [x] D частично: admin-окно получено; **RTP и Behavior Monitor включены**; **ETW-TI измерен — admin недостаточно (0x80070005, требуется PPL)**; WDAC audit-политика развёрнута, но **не активна из-за Secure Boot**; enforce не разворачивался.
- [ ] Драйвер/minifilter/ELAM/WFP — не начаты (нет подписи).

## 5. Процесс

- [ ] Независимый auto-review (вторая модель, temperature=0); M8/M9.
- [ ] `human_acceptance` для релиза.
- [ ] Red-team и chaos перед релизом.
- [x] DEVLOG ведётся; измерения сопровождаются артефактами (формат-полнота 67 %, legacy раскрыты).
- [x] `docs/status.md` — валидный UTF-8 без NUL; `docs_consistency` **13/13** (все проверки строгие).

## 6. Инфраструктура

- [x] `.gitignore`, README, LICENSE (proprietary placeholder), SECURITY, CHANGELOG.
- [x] `pyproject.toml` с build-system и extras.
- [x] CI workflow (Windows: pytest + Rust test/clippy) — файл добавлен, раннер не подключён.
- [ ] Lockfile/полный набор версий для production; текущий `requirements.lock` — снимок dev-среды.
- [ ] Подпись артефактов/репозитория обновлений.
- [ ] Резервное копирование/откат на уровне поставки (есть только откат CI-политики и настроек Defender).

## 7. Команды приёмки

```powershell
python -m pytest
python scripts\run_all.py
.\rust\gate.ps1
python scripts\docs_consistency.py
```

Критерий: все обязательные шаги зелёные, `docs_consistency` 13/13,
`docs/status.md` — валидный UTF-8 без NUL.
