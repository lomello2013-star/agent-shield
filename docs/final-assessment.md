# Финальная оценка готовности (2026-11-14)

## Закрытые внутренние P0/P1

| Пункт | Статус | Доказательство |
|---|---|---|
| FP 007 (ambient service install) | ✅ | 007 сужен по path; ambient 0 FP; tradeoff D-001 |
| Атрибуция событий | ✅ | audit `event_id`/`event_ts`/`object_path`; 10/11, 0 FP |
| Linux live | ✅ 17/17 applicable | D-012; 3 Windows-only N/A; `artifacts/linux_ebpf_live.json` |
| eBPF-агент | ✅ systemd + queue/manifest | 10 потоков, 12 audit-строк, `dropped=0`; `docs/linux-agent.md` |
| R1/R4 | ✅ 24 ч | 86400,2 с, 0 крашей/рестартов, 100 % availability, chain 373 564; root cause 0xC0000005 не воспроизведён |
| Benign/holdout | ✅ | Windows **10/11**, holdout **5/5**, **0 FP**; `WIN-17` закрыт `016A` live |
| E7/F10 | ✅ v1 accepted | E7 0.90136 @1 % / PPV 0.5642 @0.05 %; F10 13.33 %; исходные 0.95@0.05 % и 10 % — research/pilot (D-014/D-015) |
| Реальные образцы | ✅ безопасные эмуляции | D-008: реальный malware не запускается |
| status/readiness/тесты | ✅ | pytest 545, run_all 29/29, docs 13/13 |
| EV/HLK-пакет | 🧊 frozen | Inf2Cat, каталог 2366 B; EV/HLK/Partner Center — D-016 |

## Заморожено (D-016)

| Пункт | Почему | Разморозка |
|---|---|---|
| EV-сертификат / Partner Center | нужно юрлицо | ИП/ООО или партнёр |
| HLK/WHQL + production-подпись драйвера | цепочка EV→HLK→Partner Center | EV + HLK |
| WDAC CI policy signing | требует EV | EV/CI |
| Production HSM/ключ | key custody/attestation | сертифицированный HSM |

Lab-ключи — offline USB (LUKS + 2-of-3), [hsm-usb-plan.md](hsm-usb-plan.md); это
не production HSM.

## Остаточное (не блокирует v1)

- `WIN-18` — 7036 не даёт 7045: source gap, не сигнатура правила;
- 0.95 @0.05 % и FBR 10 % — research/pilot, не релизный гейт v1;
- human-review v1 — за владельцем.

## Внешние блокеры

1. EV-сертификат + Partner Center (юрлицо).
2. HLK Controller/Studio + Playlist.
3. Human-review релиза.
4. Admin-окно для E12 (не входит в v1).

v1 lab-scope закрыт; production-драйвер заморожен до юрлица/партнёра.
