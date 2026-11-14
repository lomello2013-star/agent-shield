# Финальная оценка готовности (2026-11-14)

## Закрытые внутренние P0/P1

| Пункт | Статус | Доказательство |
|---|---|---|
| FP 007 (ambient service install) | ✅ | 007 сужен по path; ambient 0 FP; tradeoff D-001 |
| Атрибуция событий | ✅ | audit `event_id`/`event_ts`/`object_path`; 9/11, 0 FP |
| Linux live | ✅ 17/17 applicable | D-012; 3 Windows-only N/A; `artifacts/linux_ebpf_live.json` |
| eBPF-агент | ✅ systemd + queue/manifest | 10 потоков, 12 audit-строк, `dropped=0`; `docs/linux-agent.md` |
| R1/R4 | ✅ 24 ч | 86400,2 с, 0 крашей/рестартов, 100 % availability, chain 373 564; root cause 0xC0000005 не воспроизведён |
| Benign/holdout | ✅ | Windows **10/11**, holdout **5/5**, **0 FP**; `WIN-17` закрыт `016A` live |
| E7/F10 | 🟡 revised | E7 0.90136 @1 %; F10 13.33 %; исходные цели пересмотрены (D-014/D-015) |
| Реальные образцы | ✅ безопасные эмуляции | D-008: реальный malware не запускается |
| status/readiness/тесты | ✅ | pytest 543, run_all 29/29, docs 13/13 |
| EV/HLK-пакет | ✅ test-signed | Inf2Cat, каталог 2366 B; EV/HLK — внешние |

## Остаточное

- R1/R4: 24-часовой soak завершён — 0 крашей/0 рестартов, 100 % availability; root cause не воспроизведён;
- E7/F10 — исходные цели не достигнуты, пересмотрены в D-014/D-015;
- `WIN-18` — 7036 не даёт 7045: source gap, не сигнатура правила;
- production-ключ/HSM для подписи Linux-агента — внешний этап (lab Ed25519 уже проверен);
- logrotate установлен (`packaging/linux/aidf-agent.logrotate`, 14 дней).

## Внешние блокеры

1. EV-сертификат (покупка/identity).
2. HLK Controller/Studio + Playlist + Partner Center.
3. Human-review релиза и подписание.

Всё остальное, что агент мог сделать в lab, закрыто.
