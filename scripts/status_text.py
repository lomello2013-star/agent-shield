"""Status document renderer (text lives here, not inside the runner).

Keeping the Russian template in a separate module written by a UTF-8 tool avoids the
class of corruption that hit `run_all.py` twice: PowerShell ANSI round-trips.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

TEXT = {
    "title": "# Статус проекта «ИИ-защитник» (user-mode)",
    "generated": "> Сгенерировано `scripts/run_all.py` — {now}. Не редактировать вручную.",
    "regression": "## Регрессионный прогон",
    "step": "Шаг",
    "result": "Результат",
    "details": "Детали",
    "total": "**Итог:** {passed}/{total} шагов успешны; обязательные провалы: {failed}.",
    "metrics": "## Ключевые измеренные числа",
    "metric": "Метрика",
    "value": "Значение",
    "source": "Источник",
    "freshness": "## Свежесть артефактов",
    "artifact": "Артефакт",
    "changed": "Изменён (UTC)",
    "age": "Возраст, мин",
    "this_run": "В этом прогоне",
    "proven": "## Что доказано измерением",
    "not_proven": "## Что НЕ доказано (и почему)",
    "blockers": "## Блокеры, требующие человека",
    "none": "нет",
}

PROVEN = [
    "Надёжностная платформа: R2/R3/R6/R8/R9/R10 — см. stage1 и chaos-отчёты.",
    "Контракты v3.0 и capability negotiation — контрактные тесты, drift-check.",
    "Детекция на реальных событиях: Linux eBPF exec/LSM/net, Windows System/Defender.",
    "Обратимые действия: suspend/resume, карантин с AES-GCM и восстановлением.",
    "Shadow ML: ONNX-инференс с подписанным ModelPack (fail-closed).",
    "IPC: JSON-RPC с ролями, замеры задержки и отказов.",
]

NOT_PROVEN = [
    "R1/R4 (доступность/сессии): нужен многочасовой soak, а не 3-минутный прогон.",
    "E7 (TPR@FPR): цель не достигнута — измерено 0,86 @1 % FPR; нужен ансамбль/данные.",
    "E11 как эффективность: матрица покрытия — полнота отображения, не red-team.",
    "E12: enforce L0 требует elevation и 2 недель audit (блокер D).",
    "Драйвер/ядро: нет подписи и WDK (блокеры A/B), спайк 5 не закрыт.",
    "Linux Secure Boot/fapolicyd: нет таргета (блокер C).",
]

BLOCKERS = [
    "A) EV-сертификат + Hardware Dev Center (подпись драйвера).",
    "B) Windows тест-VM с WDK/testsigning. C) Linux-VM с Secure Boot/fapolicyd.",
    "D) Окно с admin (RTP, WDAC audit, ETW-TI). E) rustup — закрыт (Rust-порт F19 сделан).",
]


def _registry_champion() -> str:
    """Source of truth is models/registry.json, not the stale challenger artifact."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "models", "registry.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for model in data.get("models", []):
            if model.get("role") == "champion":
                return f"{model.get('model_id')} v{model.get('version')}"
    except (OSError, ValueError):
        pass
    return "—"


def render(steps, artifacts: dict, now: datetime, art_dir: str,
           run_started_ts: float | None = None) -> str:
    def get(name: str, *path, default="—"):
        node = artifacts.get(name, {})
        for key in path:
            if isinstance(node, dict) and key in node:
                node = node[key]
            elif isinstance(node, list) and isinstance(key, int) and -len(node) <= key < len(node):
                node = node[key]
            else:
                return default
        return node

    def hits_sum(name: str, key: str = "rule_hits") -> int:
        hits = artifacts.get(name, {}).get(key, {})
        return sum(hits.values()) if isinstance(hits, dict) else 0

    lines = [TEXT["title"], "",
             TEXT["generated"].format(now=now.strftime("%Y-%m-%d %H:%M UTC")), "",
             TEXT["regression"], "",
             f"| {TEXT['step']} | {TEXT['result']} | {TEXT['details']} |",
             "|---|---|---|"]
    for step in steps:
        mark = "ok" if step.ok else ("FAIL" if step.required else "skip")
        lines.append(f"| {step.name} | {mark} | {step.detail[:160]} |")
    passed = sum(1 for s in steps if s.ok)
    failed = [s.name for s in steps if s.required and not s.ok] or TEXT["none"]
    lines += ["", TEXT["total"].format(passed=passed, total=len(steps), failed=failed), ""]

    lines += [TEXT["metrics"], "",
              f"| {TEXT['metric']} | {TEXT['value']} | {TEXT['source']} |",
              "|---|---|---|",
              f"| Сквозной конвейер (20k событий) | {get('stage4_report.json','end_to_end','records_per_s')} записей/с | stage4 |",
              f"| Потери при шторме | {get('stage4_report.json','end_to_end','lost')} | stage4 |",
              f"| R2 детекция тихого отказа | {get('stage1_report.json','R2_silent_source','max_latency_s')} с | stage1 |",
              f"| R3 MTTR | {get('stage1_report.json','R3_mttr','mttr_ms_p95')} мс | stage1 |",
              f"| R6 откат | {get('stage1_report.json','R6_update_rollback','rollback_rate')} | stage1 |",
              f"| E10 сдерживание | {get('stage7_report.json','contain_latency','contain_ms_p95')} мс | stage7 |",
              f"| Правил / покрытие обнаружения | {get('stage5_report.json','rules')} / {get('stage5_report.json','coverage','detection_pct')}% | stage5 |",
              f"| Покрытие предотвращения | {get('stage5_report.json','coverage','prevention_pct')}% | stage5 |",
              f"| IPC health p95 | {get('ipc_report.json','health','ms_p95')} мс | ipc |",
              f"| Linux exec: ядро→вердикт p95 | {get('linux_e2e.json','latency_kernel_to_user_ms','p95')} мс | linux_e2e |",
              f"| Linux LSM: чтений→вердиктов | {get('linux_lsm.json','events')} / {hits_sum('linux_lsm.json')} | linux_lsm |",
              f"| Linux net: C2-портов→вердиктов | {get('linux_net.json','c2_connects')} / {hits_sum('linux_net.json')} | linux_net |",
              f"| Windows System: событий→вердиктов | {get('windows_e2e.json','events_read')} / {get('windows_e2e.json','verdicts')} | windows_e2e |",
              f"| Windows Defender: событий→вердиктов | {get('windows_defender.json','events_read')} / {get('windows_defender.json','verdicts')} | windows_defender |",
              f"| Soak: событий / потерь | {get('soak_report.json','load','events_fed')} / {get('soak_report.json','final','lost')} | soak |",
              f"| Soak: RSS за последние 60 с | {get('soak_report.json','rss_growth_last_60s_pct')} % | soak |",
              "| Открытый дефект: длинные прогоны | **0xC0000005** (нативный краш), причина не найдена — R1/R4 не подтверждены (dev-report §14) | f11 |",
              f"| Калибровка PE: ECE | {get('calibration_report.json','ece_raw')} → {get('calibration_report.json','ece_calibrated')} | calibration |",
              f"| Калибровка: разрыв confidence/PPV | {get('calibration_report.json','consistency','max_gap')} | calibration |",
              f"| PE v2: TPR @0,05 % FPR | {get('pe_v2_report.json','operating_points',0,'tpr')} (было 0,535) | pe_v2 |",
              f"| PE v2: TPR @1 % FPR | {get('pe_v2_report.json','operating_points',3,'tpr')} (было 0,854) | pe_v2 |",
              f"| PE v2: паритет ONNX (>1e-4) | {get('ship_v2.json','export','rows_over_1e-4')}/{get('ship_v2.json','export','rows_checked')} строк | ship_v2 |",
              f"| PE v2: ECE калибровки | {get('ship_v2.json','calibration','ece_raw')} → {get('ship_v2.json','calibration','ece_calibrated')} | ship_v2 |",
              f"| PE v2: подпись пака | {get('ship_v2.json','pack','signed')} ({get('ship_v2.json','pack','code')}) | ship_v2 |",
              f"| PE v2: shadow p95 | {get('ship_v2.json','shadow','latency_ms_p95')} мс | ship_v2 |",
              f"| Champion / challenger | {_registry_champion()} / v2 ΔTPR {get('challenger_report.json','v2_minus_v1_tpr_pp')} п.п. | registry / challenger |",
              f"| Совпадение алертов v1↔v2 | {get('challenger_report.json','alert_agreement_pct')} % | challenger |",
              f"| v1↔v2: чистый прирост детекций | +{get('disagreement_report.json','net_detection_gain')} TP, ΔFP {get('disagreement_report.json','net_fp_change')} | disagreement |",
              f"| v1↔v2: доля расхождений у порога | {get('disagreement_report.json','near_threshold_share')} | disagreement |",
              f"| Ансамбль при 1 % FPR: single/union/max | {get('ensemble_report.json','budgets',1,'single','v2','tpr')} / {get('ensemble_report.json','budgets',1,'union','tpr')} / {get('ensemble_report.json','budgets',1,'max_score','tpr')} | ensemble |",
              f"| Linux memory: событий→вердиктов | {get('linux_mem.json','events')} / {get('linux_mem.json','verdicts')} (control {get('linux_mem.json','control_events')}) | linux_mem |",
              f"| Linux ptrace: событий→вердиктов | {get('linux_ptrace.json','events')} / {get('linux_ptrace.json','verdicts')} (дубли: {get('linux_ptrace.json','duplicate_verdicts')}) | linux_ptrace |",
              f"| Linux /proc/pid/mem: событий→вердиктов | {get('linux_procmem.json','events')} / {get('linux_procmem.json','verdicts')} (control {get('linux_procmem.json','control_events')}) | linux_procmem |",
              f"| Linux mprotect EXEC: своих/JIT-событий | {get('linux_mprotect.json','helper_events')} / {get('linux_mprotect.json','events')} | linux_mprotect |",
              f"| T1055: путей измерено (alert/признак) | {get('t1055_coverage.json','paths_measured')} ({get('t1055_coverage.json','alert_paths')}/{get('t1055_coverage.json','signal_paths')}) | t1055 |",
              f"| T1055: событий/вердиктов/потерь | {get('t1055_coverage.json','total_events')} / {get('t1055_coverage.json','total_verdicts')} / {get('t1055_coverage.json','total_loss')} | t1055 |",
              f"| T1055: слоёв правил (последний алерт) | {len(get('t1055_coverage.json','rule_layers',default=[]))} / {get('t1055_coverage.json','rule_layers',-1,'alerts')} | t1055 |",
              f"| Корреляция: алертов (corr/JIT/только инъекция) | {get('linux_corr.json','corr_alerts_correlated')} / {get('linux_corr.json','corr_alerts_mprotect_only')} / {get('linux_corr.json','corr_alerts_inject_only')} | linux_corr |",
              f"| Корреляция по дереву: pid / tree | {get('linux_tree.json','pid_group_alerts')} / {get('linux_tree.json','tree_group_alerts')} | linux_tree |",
              f"| Дерево: FP на «супервизор+JIT» | {get('linux_tree_fp.json','legit_supervisor_plus_jit','tree_alerts')} (benign {get('linux_tree_fp.json','benign_jit_only','tree_alerts')}) | linux_tree_fp |",
              f"| Провенанс: FP снят / детекция сохранена | {get('linux_provenance.json','fp_removed')} / {get('linux_provenance.json','detection_kept')} | linux_provenance |",
              f"| Провенанс: путей из ядра / fallback | {get('linux_provenance.json','path_resolution','kernel')} / {get('linux_provenance.json','path_resolution','fallback')} | linux_provenance |",
              f"| R2: худший случай / запас (F04) | {get('f04_r2_margin.json','incident_latency_s_max')} с / {get('f04_r2_margin.json','margin_pct')} % | f04 |",
              f"| Сигнал vs алерт (F02/F03) | A {get('f02_f03_measure.json','A_jit_only','alert_count')} / B {get('f02_f03_measure.json','B_untrusted_known','alert_count')} / C {get('f02_f03_measure.json','C_unknown_provenance','alert_count')} | f02_f03 |",
              f"| F01: разрыв confidence (isotonic / band-PPV) | {get('f01_confidence.json','gap_isotonic')} / {get('f01_confidence.json','gap_tail_ppv')} | f01 |",
              f"| F05: ppid в exec/LSM/net | {get('linux_e2e.json','ppid_events')} / {get('linux_lsm.json','ppid_events')} / {get('linux_net.json','ppid_events')} | linux_* |",
              f"| F10: FBR на holdout (звучащая политика) | {get('stage2_report.json','holdout','best','false_block_pct')} % (цель 10), покрытие {get('stage2_report.json','holdout','best','coverage_pct')} % | stage2 |",
              f"| F09: PPV на пороге алерта | {get('f09_ppv_target.json','chosen','ppv_at_prevalence')} при FPR {get('f09_ppv_target.json','chosen','fpr')} (TPR {get('f09_ppv_target.json','chosen','tpr')}) | f09 |",
              f"| F12: поведенческий TPR / benign-алерты | {get('f12_behavioral.json','behavioural_tpr')} / {get('f12_behavioral.json','benign_alerts')} | f12 |",
              f"| F13: сценарии E1–E5 (detect/prevent) | {get('f13_scenarios.json','detected')} / {get('f13_scenarios.json','prevented')} из {get('f13_scenarios.json','scenarios')} | f13 |",
              f"| Супервизор: перезапуск после kill | медиана {get('supervisor_measure.json','median_restart_latency_ms')} мс, цепочка {get('supervisor_measure.json','audit_chain','ok')} ({get('supervisor_measure.json','audit_chain','records')} записей) | supervisor |",
              f"| Доступность под супервизором | {get('soak_supervised.json','availability_pct')} % за {get('soak_supervised.json','window_s')} с, перезапусков {get('soak_supervised.json','restarts')} | soak_supervised |",
              ""]

    lines += [TEXT["freshness"], "",
              f"| {TEXT['artifact']} | {TEXT['changed']} | {TEXT['age']} | {TEXT['this_run']} |",
              "|---|---|---|---|"]
    now_ts = now.timestamp()
    hidden = ("_stdout", "dev_keys", "soak_partial")
    for name in sorted(artifacts):
        if any(marker in name for marker in hidden):
            continue
        path = os.path.join(art_dir, name)
        try:
            mtime = os.path.getmtime(path)
            fresh = "—" if run_started_ts is None else (
                "да" if mtime >= run_started_ts else "нет (из прошлого прогона)")
            lines.append(f"| {name} | "
                         f"{datetime.fromtimestamp(mtime, timezone.utc).strftime('%H:%M')} | "
                         f"{(now_ts - mtime) / 60.0:.0f} | {fresh} |")
        except OSError:
            lines.append(f"| {name} | — | — | — |")
    lines.append("")

    lines += [TEXT["proven"]] + [f"- {item}" for item in PROVEN] + [""]
    lines += [TEXT["not_proven"]] + [f"- {item}" for item in NOT_PROVEN] + [""]
    lines += [TEXT["blockers"]] + BLOCKERS + [""]
    return "\n".join(lines) + "\n"
