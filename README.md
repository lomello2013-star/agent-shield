# «ИИ-защитник»

Лёгкий EDR-прототип для Windows + Linux: user-mode платформа обнаружения и
реагирования с измеренной надёжностью, детекцией на реальных событиях и
обратимыми действиями.

> **Статус:** исследовательский прототип, **не production-релиз**. Готовность
> к production ≈35–40 %; открыты R1/R4 (длительный soak), E7/E12, Windows-ядро,
> независимое ревью и релизный контур. См. [docs/release-checklist.md](docs/release-checklist.md).

## Что уже есть

- `core/` — ingest, нормализация, 28 правил, gate, response, self-protect, IPC,
  ModelPack/ML shadow, reliability-платформа.
- `schemas/v3/` — 21 JSON-схема контракта v3.0.
- `rules/` — правила и матрица ATT&CK.
- `rust/` — Rust-порт 12 модулей (133 теста, Python-wire IPC, ML 50k, gate/bench).
- `artifacts/` — измерения и артефакты DEVLOG.
- `DEVLOG.md` — журнал разработки с методом, числами и вердиктами.

## Быстрый старт

Требуется Python 3.12+.

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python scripts\run_all.py
```

Rust-контур (Windows, без Visual Studio Build Tools — используется `rust-lld`):

```powershell
python .\rust\export_holdout.py   # 50k ML-данные (476 МБ, не коммитятся)
.\rust\gate.ps1                  # fmt + clippy + 133 теста
```

Linux-полосы требуют WSL2 с root: `scripts/run_linux_*.sh`. Без WSL шаги
помечаются `skip`.

## Структура

| Путь | Назначение |
|---|---|
| `core/` | runtime-модули user-mode |
| `tests/` | unit/contract/integration-тесты |
| `scripts/` | e2e, измерения, генераторы, `run_all.py` |
| `rules/`, `schemas/` | правила и контракты |
| `rust/` | Rust-порт и его gate |
| `docs/` | нормативные документы, отчёты, release checklist |
| `artifacts/` | измерения; большие логи — в `_stdout/` |

## Ограничения

- **Драйвера нет**: нужны EV-сертификат, WDK, human-review (блокеры A/B).
- **R1/R4 не доказаны**: soak падает нативным `0xC0000005`; нужен 24-часовой
  прогон на always-on VM.
- **E7 не достигнута** (0,6724 @0,05 % FPR против 0,95), **E12** — 13,3 % FBR
  в audit против <0,1 % в enforce.
- **Нет независимого auto-review** и `human_acceptance`.
- **Модели и правила** пока рассчитаны на запуск из checkout; полноценная
  упаковка данных — в release checklist.
- **Секреты**: `secrets/` исключён из git; dev-ключ нельзя использовать в
  production.

## Безопасность

Не запускайте на production-хостах. Для уязвимостей — см. [SECURITY.md](SECURITY.md).

## Лицензия

Proprietary, all rights reserved; условия использования определяет владелец
проекта. См. [LICENSE](LICENSE).
