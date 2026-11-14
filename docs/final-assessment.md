# Финальная оценка готовности (2026-11-14)

## Закрытые внутренние P0/P1

| Пункт | Статус | Доказательство |
|---|---|---|
| FP 007 (ambient service install) | ✅ | 007 сужен по path; ambient 0 FP; tradeoff D-001 |
| Атрибуция событий | ✅ | audit `event_id`/`event_ts`/`object_path`; 9/11, 0 FP |
| Linux live | ✅ 17/17 applicable | D-012; 3 Windows-only N/A; `artifacts/linux_ebpf_live.json` |
| eBPF-агент | ✅ systemd-прототип | 10 потоков, 12 audit-строк; `docs/linux-agent.md` |
| Benign/holdout | ✅ | Windows 0 FP, holdout 4/5; Linux controls |
| Реальные образцы | ✅ безопасные эмуляции | D-008: реальный malware не запускается |
| status/readiness/тесты | ✅ | 533 passed, run_all 29/29, docs 13/13 |
| EV/HLK-пакет | ✅ test-signed | Inf2Cat, каталог 2366 B; EV/HLK — внешние |

## Остаточное (не блокирует детекцию)

- подпись и очередь/backpressure Linux-агента — hardening;
- alert-only правило для generic service install — enhancement (D-001);
- logrotate установлен (`packaging/linux/aidf-agent.logrotate`, 14 дней).

## Внешние блокеры

1. EV-сертификат (покупка/identity).
2. HLK Controller/Studio + Playlist + Partner Center.
3. Human-review релиза и подписание.

Всё остальное, что агент мог сделать в lab, закрыто.
