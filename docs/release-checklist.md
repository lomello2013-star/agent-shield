# Release checklist

> Статус на 2026-11-14: **v1 lab/PoC готов; production-драйвер заморожен**.
> v1 scope и freeze — [v1-release-scope.md](v1-release-scope.md), D-016.

## 0. v1 scope / freeze

- [x] E7 v1: TPR ≥0.90 @1 % FPR (0.90136); PPV 0.5642 @0.05 % (D-014).
- [x] F10 v1: FBR ≤15 % lab (13.33 %); 10 % — pilot feed (D-015).
- [ ] **FROZEN:** EV, Partner Center, HLK/WHQL, production-подпись драйвера,
  production HSM/ключ (D-016). Не начинать до юрлица/партнёра.
- [x] Lab-ключи: offline USB (LUKS + 2-of-3), [hsm-usb-plan.md](hsm-usb-plan.md).

## 1. Код и контракты

- [x] User-mode ядро, 30 правил, 21 схема, тесты Python (**545 passed / 0 skip**, включает STML; `run_all` 29/29).
- [x] Rust-порт 12 модулей: 133 теста, gate, benchmark, Python-wire IPC.
- [x] Immutable-константы не менялись; fingerprint стабилен.
- [x] `secrets/` исключён из git; dev-ключ не production.
- [x] **Windows-служба `AIDefender`** установлена (ctypes SCM-хост, автозапуск, start/stop ~0,3 с).
- [ ] Пакетная поставка `rules/` и `models/` вне checkout.
- [ ] Полный `pip install` + запуск демона в чистом окружении (сейчас проверяется только editable-install).
- [ ] Installer (MSI/deb/rpm) и systemd unit для Linux — **не сделано**.

## 2. Надёжность

- [x] R1/R4: **24-часовой soak** без `0xC0000005`: 86 400,2 с, 0 рестартов, 100 % availability, 373 564 записи.
- [ ] 7-дневный soak на always-on VM.
- [x] R2/R3/R6/R8/R9/R10 измерены (см. `artifacts/stage1_report.json`); R3 дополнен супервизором (перезапуск ~0,28 с).
- [ ] R7 (FP-отключения) — нужен пилот.

## 3. Эффективность

- [x] E7 v1 ≥0,90 @1 % FPR (0,90136); исходная 0,95 @0,05 % — research (D-014).
- [ ] **FROZEN:** E12 enforce <0,1 % — нужен admin/RTP/WDAC audit; не входит в v1 (D-016).
- [ ] E1–E6/E8 — red-team 20 сценариев/ОС и 7-дневный пилот.
- [x] E9 рабочая точка 56,4 % @0,05 % FPR; E10 в цели.
- [x] E11 28/28 на авторских фикстурах (не red-team).

## 4. Платформа и подпись

- [ ] **FROZEN:** A: EV-сертификат + Hardware Dev Center (D-016).
- [ ] **FROZEN:** production-подпись драйвера/WHQL/HLK (D-016).
- [x] B: Windows VM + WDK/test-signing — lab-драйвер проверен.
- [x] C: Linux VM + Secure Boot/fapolicyd/IMA — lab-проверки выполнены.
- [ ] **FROZEN:** E12/WDAC enforce — admin/EV, не входит в v1.
- [x] Драйвер/minifilter — test-signed lab; production-подпись заморожена.

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
