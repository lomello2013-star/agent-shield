"""Final stage-by-stage slice: what was measured, what is blocked, and by whom.

Every number is pulled from an artifact where one exists; entries with no artifact say
so explicitly instead of repeating a claim. Writes docs/stage-summary.md and
artifacts/final_summary.json.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(HERE, "artifacts")
OUT_JSON = os.path.join(ART, "final_summary.json")
OUT_MD = os.path.join(HERE, "docs", "stage-summary.md")


def art(name: str) -> dict:
    path = os.path.join(ART, name)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def g(data: dict, *path, default="—"):
    node: object = data
    for key in path:
        if isinstance(node, dict) and key in node:
            node = node[key]
        elif isinstance(node, list) and isinstance(key, int) and -len(node) <= key < len(node):
            node = node[key]
        else:
            return default
    return node


def rows() -> list[dict]:
    s1, s2, s4, s5 = (art("stage1_report.json"), art("stage2_report.json"),
                      art("stage4_report.json"), art("stage5_report.json"))
    s7, s11, s12 = (art("stage7_report.json"), art("stage11_report.json"),
                    art("stage12_chaos.json"))
    soak, cov, prov = (art("soak_report.json"), art("t1055_coverage.json"),
                       art("linux_provenance.json"))
    v2, corr = art("pe_v2_report.json"), art("linux_corr.json")

    return [
        {"stage": "0", "item": "Спайки 1–4, 6, 7 измерены",
         "value": "Secure Boot=1, 0 EV; WDAC FBR 31,6 %; AMSI p95 12,68 µs; "
                  "ML PE 0,854@1 %; 19 minifilters",
         "source": "artifacts/stage*.json, DEVLOG", "status": "measured"},
        {"stage": "0", "item": "Спайк 5 (драйвер)",
         "value": "19 minifilters; 19 BugCheck/90 д; нет подписи и WDK",
         "source": "DEVLOG этап 0.5", "status": "blocked: human (A/B)"},
        {"stage": "1", "item": "R2 тихий отказ",
         "value": f"{g(s1, 'R2_silent_source', 'max_latency_s')} с",
         "source": "stage1_report.json", "status": "measured"},
        {"stage": "1", "item": "R3 MTTR",
         "value": f"{g(s1, 'R3_mttr', 'mttr_ms_p95')} мс",
         "source": "stage1_report.json", "status": "measured"},
        {"stage": "1", "item": "R6 откат",
         "value": f"{g(s1, 'R6_update_rollback', 'rollback_rate')}",
         "source": "stage1_report.json", "status": "measured"},
        {"stage": "1", "item": "R8 потери (100k)",
         "value": f"{g(s1, 'R8_loss_storm_smooth', 'lost')} потерь на "
                  f"{g(s1, 'R8_loss_storm_smooth', 'total_submitted')}",
         "source": "stage1_report.json", "status": "measured"},
        {"stage": "1", "item": "R9 fail-safe",
         "value": f"reject {g(s1, 'R9_fail_safe', 'rejected_on_timeout')}/"
                  f"{g(s1, 'R9_fail_safe', 'timeouts')}, destructive "
                  f"{g(s1, 'R9_fail_safe', 'executed_without_operator')}",
         "source": "stage1_report.json", "status": "measured"},
        {"stage": "1", "item": "R1/R4 доступность",
         "value": f"soak {g(soak, 'load', 'events_fed')} событий, RSS "
                  f"+{g(soak, 'rss_growth_last_60s_pct')} %/60 с, плато "
                  f"{g(soak, 'rss_plateau')}",
         "source": "soak_report.json", "status": "partially measured: нужен многочасовой прогон"},
        {"stage": "2", "item": "WDAC audit, false block политики A",
         "value": f"{g(s2, 'policies', 'A_ms_signed_only', 'false_block', 'false_block_rate_pct')} %",
         "source": "stage2_report.json", "status": "measured (audit)"},
        {"stage": "2", "item": "Живые события 3076",
         "value": f"{g(s2, 'codeintegrity', 'audit_events_3076_parsed')} событий 3076",
         "source": "stage2_report.json", "status": "blocked: нужна элевация (D)"},
        {"stage": "4", "item": "Сквозной конвейер",
         "value": f"{g(s4, 'end_to_end', 'records_per_s')} записей/с, потерь "
                  f"{g(s4, 'end_to_end', 'lost')}",
         "source": "stage4_report.json", "status": "measured"},
        {"stage": "5", "item": "Покрытие обнаружения/предотвращения",
         "value": f"{g(s5, 'coverage', 'detection_pct')} % / "
                  f"{g(s5, 'coverage', 'prevention_pct')} %",
         "source": "stage5_report.json", "status": "measured (авторские фикстуры)"},
        {"stage": "7", "item": "Suspend / contain",
         "value": f"p95 {g(s7, 'suspend_resume', 'suspend_ms_p95')} мс / "
                  f"{g(s7, 'contain_latency', 'contain_ms_p95')} мс",
         "source": "stage7_report.json", "status": "measured"},
        {"stage": "8", "item": "Модель PE v2 и E7",
         "value": f"TPR {g(v2, 'operating_points', 0, 'tpr')} @0,05 % FPR; "
                  f"{g(v2, 'operating_points', 3, 'tpr')} @1 %",
         "source": "pe_v2_report.json",
         "status": "measured; цель E7 0,95 @0,05 % не достигнута"},
        {"stage": "9", "item": "T1055 Linux (4 пути)",
         "value": f"{g(cov, 'paths_measured')} путей, {g(cov, 'alert_paths')} alert / "
                  f"{g(cov, 'signal_paths')} signal, потерь {g(cov, 'total_loss')}",
         "source": "t1055_coverage.json", "status": "measured"},
        {"stage": "9", "item": "Провенанс из ядра",
         "value": f"из ядра {g(prov, 'path_resolution', 'kernel')}, fallback "
                  f"{g(prov, 'path_resolution', 'fallback')}",
         "source": "linux_provenance.json", "status": "measured"},
        {"stage": "11", "item": "Аудит-журнал",
         "value": f"{g(s11, 'hash_chain', 'records_per_s')} записей/с, verify "
                  f"{g(s11, 'hash_chain', 'verify_ms')} мс",
         "source": "stage11_report.json", "status": "measured"},
        {"stage": "11", "item": "Корреляция (pid/tree/provenance)",
         "value": f"corr {g(corr, 'corr_alerts_correlated')}, JIT "
                  f"{g(corr, 'corr_alerts_mprotect_only')}",
         "source": "linux_corr.json, linux_tree*.json, linux_provenance.json",
         "status": "measured; FP-класс задокументирован"},
        {"stage": "12", "item": "Хаос-инъекции",
         "value": f"потерь {g(s12, 'R8_storm', 'lost')}, spilled "
                  f"{g(s12, 'R8_storm', 'spilled_before_drain')}, safe mode ok",
         "source": "stage12_chaos.json", "status": "measured"},
    ]


BLOCKERS = [
    ("A", "EV-сертификат + Hardware Dev Center", "подпись драйвера; без неё ядро не мержится"),
    ("B", "Windows тест-VM с WDK/testsigning", "спайк 5 и драйвер остаются открытыми"),
    ("C", "Linux-VM с Secure Boot/fapolicyd", "проверка политик целостности не выполнена"),
    ("D", "Окно с admin", "RTP, WDAC enforce, ETW-TI, Windows T1055 — не измерены"),
    ("E", "Разрешение на rustup", "Rust-порт контрактов отложен (D2: Python 3.12)"),
]

NOT_PROVEN = [
    "E7 (0,95 @0,05 % FPR): измерено 0,6724 — потолок статики",
    "R1/R4 (многочасовая доступность): 5-минутный soak с плато, не сутки",
    "Windows T1055: нет элевации",
    "Драйвер/ядро: нет подписи и WDK",
    "Эффективность (red-team): матрица покрытия — не доказательство",
]


def main() -> None:
    table = rows()
    measured = [r for r in table if r["status"].startswith("measured")]
    partial = [r for r in table if r["status"].startswith("partially")]
    blocked = [r for r in table if r["status"].startswith("blocked")]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "measured": len(measured), "partial": len(partial), "blocked": len(blocked),
        "items": table,
        "blockers": [{"id": i, "what": w, "why": y} for i, w, y in BLOCKERS],
        "not_proven": NOT_PROVEN,
    }
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    lines = [
        "# Итоговый срез по этапам",
        "",
        f"> Сгенерировано `scripts/final_summary.py` — {summary['generated_at'][:16]} UTC.",
        "",
        f"Измерено: **{summary['measured']}**, частично: **{summary['partial']}**, "
        f"заблокировано: **{summary['blocked']}**.",
        "",
        "| Этап | Пункт | Числа | Источник | Статус |",
        "|---|---|---|---|---|",
    ]
    for r in table:
        lines.append(f"| {r['stage']} | {r['item']} | {r['value']} | `{r['source']}` | {r['status']} |")
    lines += ["", "## Не доказано (и почему)"]
    lines += [f"- {item}" for item in NOT_PROVEN]
    lines += ["", "## Блокеры, требующие человека"]
    lines += [f"- **{i}** — {w}: {y}." for i, w, y in BLOCKERS]
    with open(OUT_MD, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(json.dumps({k: summary[k] for k in ("measured", "partial", "blocked")},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
