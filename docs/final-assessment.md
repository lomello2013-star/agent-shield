# Финальная оценка готовности (2026-11-14)

## Закрытые внутренние P0/P1

| Пункт | Статус | Доказательство |
|---|---|---|
| FP 007 (ambient service install) | ✅ | 007 сужен по path; ambient 0 FP; tradeoff D-001 |
| Атрибуция событий | ✅ | audit `event_id`/`event_ts`/`object_path`; 9/11, 0 FP |
| Linux live | ✅ 17/17 applicable | D-012; 3 Windows-only N/A; `artifacts/linux_ebpf_live.json` |
| eBPF-агент | ✅ systemd + queue/manifest | 10 потоков, 12 audit-строк, `dropped=0`; `docs/linux-agent.md` |
| Benign/holdout | 🟡 | Windows 0 FP, holdout 4/5; `WIN-17` закрыт правилом `016A` на fixture, live rerun — open |
| E7/F10 | 🟡 revised | E7 0.90136 @1 %; F10 13.33 %; исходные цели пересмотрены (D-014/D-015) |
| Реальные образцы | ✅ безопасные эмуляции | D-008: реальный malware не запускается |
| status/readiness/тесты | ✅ | pytest 543, run_all 29/29, docs 13/13 |
| EV/HLK-пакет | ✅ test-signed | Inf2Cat, каталог 2366 B; EV/HLK — внешние |

## Остаточное

- R1/R4: 24-часовой soak идёт; на 23,7 ч — 0 крашей/0 рестартов, финал после 24 ч;
- E7/F10 — исходные цели не достигнуты, пересмотрены в D-014/D-015;
- `WIN-17` — правило `016A` и fixture готовы, live rerun блокируется IPC-зависанием сервиса;
- подпись Linux-агента (SHA256-манифест уже есть) — open;
- logrotate установлен (`packaging/linux/aidf-agent.logrotate`, 14 дней).

## Внешние блокеры

1. EV-сертификат (покупка/identity).
2. HLK Controller/Studio + Playlist + Partner Center.
3. Human-review релиза и подписание.

Всё остальное, что агент мог сделать в lab, закрыто.
