# Итоговый срез по этапам

> Сгенерировано `scripts/final_summary.py` — 2026-11-14T09:48 UTC.

Измерено: **16**, частично: **1**, заблокировано: **2**.

| Этап | Пункт | Числа | Источник | Статус |
|---|---|---|---|---|
| 0 | Спайки 1–4, 6, 7 измерены | Secure Boot=1, 0 EV; WDAC FBR 31,6 %; AMSI p95 12,68 µs; ML PE 0,854@1 %; 19 minifilters | `artifacts/stage*.json, DEVLOG` | measured |
| 0 | Спайк 5 (драйвер) | 19 minifilters; 19 BugCheck/90 д; нет подписи и WDK | `DEVLOG этап 0.5` | blocked: human (A/B) |
| 1 | R2 тихий отказ | 59.5 с | `stage1_report.json` | measured |
| 1 | R3 MTTR | 110.5 мс | `stage1_report.json` | measured |
| 1 | R6 откат | 1.0 | `stage1_report.json` | measured |
| 1 | R8 потери (100k) | 0 потерь на 100000 | `stage1_report.json` | measured |
| 1 | R9 fail-safe | reject 100/100, destructive 0 | `stage1_report.json` | measured |
| 1 | R1/R4 доступность | soak 35653 событий, RSS +0.0 %/60 с, плато True | `soak_report.json` | partially measured: нужен многочасовой прогон |
| 2 | WDAC audit, false block политики A | 46.0 % | `stage2_report.json` | measured (audit) |
| 2 | Живые события 3076 | 0 событий 3076 | `stage2_report.json` | blocked: нужна элевация (D) |
| 4 | Сквозной конвейер | 7705.0 записей/с, потерь 0 | `stage4_report.json` | measured |
| 5 | Покрытие обнаружения/предотвращения | 100.0 % / 100.0 % | `stage5_report.json` | measured (авторские фикстуры) |
| 7 | Suspend / contain | p95 0.157 мс / 4.257 мс | `stage7_report.json` | measured |
| 8 | Модель PE v2 и E7 | TPR 0.67242 @0,05 % FPR; 0.90136 @1 % | `pe_v2_report.json` | measured; цель E7 0,95 @0,05 % не достигнута |
| 9 | T1055 Linux (4 пути) | 4 путей, 3 alert / 1 signal, потерь 0 | `t1055_coverage.json` | measured |
| 9 | Провенанс из ядра | из ядра 20, fallback 0 | `linux_provenance.json` | measured |
| 11 | Аудит-журнал | 1077.0 записей/с, verify 21.886 мс | `stage11_report.json` | measured |
| 11 | Корреляция (pid/tree/provenance) | corr 5, JIT 0 | `linux_corr.json, linux_tree*.json, linux_provenance.json` | measured; FP-класс задокументирован |
| 12 | Хаос-инъекции | потерь 0, spilled 16500, safe mode ok | `stage12_chaos.json` | measured |

## Не доказано (и почему)
- E7 (0,95 @0,05 % FPR): измерено 0,6724 — потолок статики
- R1/R4 (многочасовая доступность): 5-минутный soak с плато, не сутки
- Windows T1055: нет элевации
- Драйвер/ядро: нет подписи и WDK
- Эффективность (red-team): матрица покрытия — не доказательство

## Блокеры, требующие человека
- **A** — EV-сертификат + Hardware Dev Center: подпись драйвера; без неё ядро не мержится.
- **B** — Windows тест-VM с WDK/testsigning: спайк 5 и драйвер остаются открытыми.
- **C** — Linux-VM с Secure Boot/fapolicyd: проверка политик целостности не выполнена.
- **D** — Окно с admin: RTP, WDAC enforce, ETW-TI, Windows T1055 — не измерены.
- **E** — Разрешение на rustup: закрыт: rustc/cargo 1.100.0, Rust-порт F19 сделан (133 теста).
