# Статус проекта «ИИ-защитник» (user-mode)

> Сгенерировано `scripts/run_all.py` — 2026-11-14 12:27 UTC. Не редактировать вручную.

## Регрессионный прогон

| Шаг | Результат | Детали |
|---|---|---|
| tests | ok | 531 passed in 26.43s |
| rules_and_coverage | ok | rules=28 lint=0 detection=100.0% prevention=100.0% |
| schema_drift | ok | in sync |
| immutable_policy | ok | fingerprint=d8ae913401ea contract=ok |
| artifacts | ok | present=39/39 |
| windows_system_e2e | ok | events=60 verdicts=1 |
| windows_defender_e2e | ok | events=200 verdicts=29 before_classification=200 |
| windows_chaos | ok | final_verdicts=2 loss=0 |
| linux_exec_e2e | ok | exit=0 |
| linux_lsm_e2e | ok | exit=0 |
| linux_net_e2e | ok | exit=0 stderr=TimeoutError: timed out |
| linux_mem_e2e | ok | exit=0 |
| linux_ptrace_e2e | ok | exit=0 |
| linux_procmem_e2e | ok | exit=0 |
| linux_mprotect_e2e | ok | exit=0 |
| linux_corr_e2e | ok | exit=0 |
| linux_tree_e2e | ok | exit=0 |
| linux_tree_fp | ok | exit=0 |
| linux_provenance | ok | exit=0 |
| gen_docs | ok | exit=0 bytes=540 |
| f04_r2_margin | ok | exit=0 bytes=321 |
| f02_f03_signal_levels | ok | exit=0 bytes=2873 |
| f01_confidence_gap | ok | exit=0 bytes=506 stderr=[0;93m2026-11-14 15:26:58.0145261 [W:onnxruntime:, execution_frame.cc:913 onnxruntime::ExecutionFrame::VerifyOutputSizes |
| f09_ppv_target | ok | exit=0 bytes=1601 |
| f12_behavioral | ok | exit=0 bytes=2623 |
| f13_scenarios | ok | exit=0 bytes=2502 |
| supervisor_measure | ok | exit=0 bytes=1135 |
| final_summary | ok | exit=0 bytes=7266 |
| docs_consistency | ok | exit=0 bytes=1345 |

**Итог:** 29/29 шагов успешны; обязательные провалы: нет.

## Ключевые измеренные числа

| Метрика | Значение | Источник |
|---|---|---|
| Сквозной конвейер (20k событий) | 7705.0 записей/с | stage4 |
| Потери при шторме | 0 | stage4 |
| R2 детекция тихого отказа | 59.5 с | stage1 |
| R3 MTTR | 110.5 мс | stage1 |
| R6 откат | 1.0 | stage1 |
| E10 сдерживание | 4.257 мс | stage7 |
| Правил / покрытие обнаружения | 28 / 100.0% | stage5 |
| Покрытие предотвращения | 100.0% | stage5 |
| IPC health p95 | 1.884 мс | ipc |
| Linux exec: ядро→вердикт p95 | 0.35 мс | linux_e2e |
| Linux LSM: чтений→вердиктов | 200 / 200 | linux_lsm |
| Linux net: C2-портов→вердиктов | 200 / 115 | linux_net |
| Windows System: событий→вердиктов | 60 / 1 | windows_e2e |
| Windows Defender: событий→вердиктов | 200 / 29 | windows_defender |
| Soak: событий / потерь | 35653 / 0 | soak |
| Soak: RSS за последние 60 с | 0.0 % | soak |
| Открытый дефект: длинные прогоны | **0xC0000005** (нативный краш), причина не найдена — R1/R4 не подтверждены (dev-report §14) | f11 |
| Калибровка PE: ECE | 0.037634 → 0.005498 | calibration |
| Калибровка: разрыв confidence/PPV | 0.0397 | calibration |
| PE v2: TPR @0,05 % FPR | 0.67242 (было 0,535) | pe_v2 |
| PE v2: TPR @1 % FPR | 0.90136 (было 0,854) | pe_v2 |
| PE v2: паритет ONNX (>1e-4) | 4/500 строк | ship_v2 |
| PE v2: ECE калибровки | 0.05328 → 0.00363 | ship_v2 |
| PE v2: подпись пака | True (ok) | ship_v2 |
| PE v2: shadow p95 | 0.181 мс | ship_v2 |
| Champion / challenger | aidf-pe-ember-v2 v2.0.0 / v2 ΔTPR 2.61 п.п. | registry / challenger |
| Совпадение алертов v1↔v2 | 96.02 % | challenger |
| v1↔v2: чистый прирост детекций | +65 TP, ΔFP 0 | disagreement |
| v1↔v2: доля расхождений у порога | 0.5025 | disagreement |
| Ансамбль при 1 % FPR: single/union/max | 0.9067 / 0.9074 / 0.9108 | ensemble |
| Linux memory: событий→вердиктов | 100 / 100 (control 0) | linux_mem |
| Linux ptrace: событий→вердиктов | 100 / 100 (дубли: False) | linux_ptrace |
| Linux /proc/pid/mem: событий→вердиктов | 100 / 100 (control 0) | linux_procmem |
| Linux mprotect EXEC: своих/JIT-событий | 100 / 100 | linux_mprotect |
| T1055: путей измерено (alert/признак) | 4 (3/1) | t1055 |
| T1055: событий/вердиктов/потерь | 400 / 400 / 0 | t1055 |
| T1055: слоёв правил (последний алерт) | 4 / 1 | t1055 |
| Корреляция: алертов (corr/JIT/только инъекция) | 5 / 0 / 0 | linux_corr |
| Корреляция по дереву: pid / tree | 0 / 1 | linux_tree |
| Дерево: FP на «супервизор+JIT» | 1 (benign 0) | linux_tree_fp |
| Провенанс: FP снят / детекция сохранена | True / True | linux_provenance |
| Провенанс: путей из ядра / fallback | 20 / 0 | linux_provenance |
| R2: худший случай / запас (F04) | 45.25 с / 24.6 % | f04 |
| Сигнал vs алерт (F02/F03) | A 0 / B 6 / C 5 | f02_f03 |
| F01: разрыв confidence (isotonic / band-PPV) | 0.0124 / 0.0111 | f01 |
| F05: ppid в exec/LSM/net | 200 / 200 / 115 | linux_* |
| F10: FBR на holdout (звучащая политика) | 13.3333 % (цель 10), покрытие 86.6667 % | stage2 |
| F09: PPV на пороге алерта | 0.5642 при FPR 0.00052 (TPR 0.67242) | f09 |
| F12: поведенческий TPR / benign-алерты | 1.0 / 0 | f12 |
| F13: сценарии E1–E5 (detect/prevent) | 9 / 9 из 10 | f13 |
| Супервизор: перезапуск после kill | медиана 285.1 мс, цепочка True (12 записей) | supervisor |
| Доступность под супервизором | 100.0 % за 3600.2 с, перезапусков 0 | soak_supervised |

## Свежесть артефактов

| Артефакт | Изменён (UTC) | Возраст, мин | В этом прогоне |
|---|---|---|---|
| agent-stml-compatibility.json | 11:24 | 63 | нет (из прошлого прогона) |
| audit_bench.json | 12:36 | 2871 | нет (из прошлого прогона) |
| calibration_report.json | 17:48 | 2558 | нет (из прошлого прогона) |
| challenger_report.json | 17:58 | 2548 | нет (из прошлого прогона) |
| chaos_report.json | 12:34 | 2872 | нет (из прошлого прогона) |
| devlog_audit.json | 12:26 | 0 | да |
| disagreement_report.json | 13:47 | 2799 | нет (из прошлого прогона) |
| docker_matrix.json | 12:53 | 2854 | нет (из прошлого прогона) |
| docs_consistency.json | 12:27 | 0 | да |
| ensemble_report.json | 13:49 | 2798 | нет (из прошлого прогона) |
| etwti_t1055.json | 18:33 | 1073 | нет (из прошлого прогона) |
| f01_confidence.json | 12:26 | 0 | да |
| f02_f03_measure.json | 12:26 | 0 | да |
| f04_r2_margin.json | 12:26 | 0 | да |
| f08_tail.json | 18:59 | 2487 | нет (из прошлого прогона) |
| f09_ppv_target.json | 12:26 | 0 | да |
| f11_bisect.json | 19:40 | 2447 | нет (из прошлого прогона) |
| f11_controls.json | 00:46 | 2141 | нет (из прошлого прогона) |
| f11_health_livelock.json | 19:11 | 2475 | нет (из прошлого прогона) |
| f11_health_probe_1500.json | 19:11 | 2475 | нет (из прошлого прогона) |
| f11_health_probe_summary.json | 19:11 | 2475 | нет (из прошлого прогона) |
| f11_pydantic_focus.json | 22:56 | 2250 | нет (из прошлого прогона) |
| f11_pydantic_stress.json | 21:07 | 2360 | нет (из прошлого прогона) |
| f11_repeat.json | 00:10 | 2177 | нет (из прошлого прогона) |
| f12_behavioral.json | 12:26 | 0 | да |
| f13_scenarios.json | 12:26 | 0 | да |
| final_summary.json | 12:27 | 0 | да |
| gate_report.json | 12:31 | 2875 | нет (из прошлого прогона) |
| gen_docs.json | 12:26 | 0 | да |
| ipc_report.json | 12:44 | 2862 | нет (из прошлого прогона) |
| linux_corr.json | 12:26 | 1 | да |
| linux_e2e.json | 12:24 | 2 | да |
| linux_ebpf_live.json | 12:23 | 3 | нет (из прошлого прогона) |
| linux_fapolicyd.json | 08:42 | 225 | нет (из прошлого прогона) |
| linux_ima_appraise.json | 08:46 | 221 | нет (из прошлого прогона) |
| linux_load.json | 12:53 | 2854 | нет (из прошлого прогона) |
| linux_lsm.json | 12:24 | 2 | да |
| linux_mem.json | 12:25 | 2 | да |
| linux_mprotect.json | 12:25 | 1 | да |
| linux_net.json | 12:24 | 2 | да |
| linux_procmem.json | 12:25 | 1 | да |
| linux_provenance.json | 12:26 | 0 | да |
| linux_ptrace.json | 12:25 | 2 | да |
| linux_tree.json | 12:26 | 1 | да |
| linux_tree_fp.json | 12:26 | 0 | да |
| pe_v2_report.json | 13:43 | 2804 | нет (из прошлого прогона) |
| redteam20_windows.json | 11:31 | 55 | нет (из прошлого прогона) |
| redteam_windows.json | 09:40 | 166 | нет (из прошлого прогона) |
| release_engineering.json | 23:37 | 2209 | нет (из прошлого прогона) |
| report_metrics.json | 17:18 | 2588 | нет (из прошлого прогона) |
| run_all.json | 12:27 | -0 | да |
| rust_bench.json | 23:20 | 2227 | нет (из прошлого прогона) |
| rust_gate.json | 23:26 | 2221 | нет (из прошлого прогона) |
| rust_ml_holdout_report.json | 22:23 | 2284 | нет (из прошлого прогона) |
| rust_ml_holdout_state.json | 22:23 | 2284 | нет (из прошлого прогона) |
| rust_port_slice1.json | 21:16 | 2350 | нет (из прошлого прогона) |
| rust_port_slice2.json | 21:29 | 2337 | нет (из прошлого прогона) |
| rust_port_slice3.json | 21:37 | 2329 | нет (из прошлого прогона) |
| rust_port_slice4.json | 21:42 | 2324 | нет (из прошлого прогона) |
| rust_port_slice5.json | 22:10 | 2296 | нет (из прошлого прогона) |
| rust_port_slice6.json | 22:18 | 2288 | нет (из прошлого прогона) |
| rust_port_slice7.json | 22:57 | 2250 | нет (из прошлого прогона) |
| rust_port_slice8.json | 23:26 | 2220 | нет (из прошлого прогона) |
| ship_v2.json | 13:43 | 2803 | нет (из прошлого прогона) |
| soak_6h_2026-11-13.json | 18:01 | 1105 | нет (из прошлого прогона) |
| soak_before_hyperv_2026-11-13.json | 19:18 | 1029 | нет (из прошлого прогона) |
| soak_before_reboot_2026-11-13.json | 18:47 | 1060 | нет (из прошлого прогона) |
| soak_report.json | 11:50 | 1477 | нет (из прошлого прогона) |
| soak_supervised.json | 11:13 | 1514 | нет (из прошлого прогона) |
| soak_supervised_partial.json | 12:26 | 0 | да |
| stage11_report.json | 12:33 | 2874 | нет (из прошлого прогона) |
| stage12_chaos.json | 12:24 | 2 | да |
| stage1_report.json | 12:14 | 2893 | нет (из прошлого прогона) |
| stage2_report.json | 18:08 | 2538 | нет (из прошлого прогона) |
| stage4_report.json | 12:25 | 2882 | нет (из прошлого прогона) |
| stage5_report.json | 18:03 | 2544 | нет (из прошлого прогона) |
| stage7_report.json | 12:30 | 2877 | нет (из прошлого прогона) |
| stage8_report.json | 12:28 | 2879 | нет (из прошлого прогона) |
| stml_phase_a.json | 12:18 | 9 | нет (из прошлого прогона) |
| stml_readiness.json | 12:26 | 0 | да |
| stml_rust_p1.json | 12:15 | 11 | нет (из прошлого прогона) |
| stml_rust_p2.json | 12:21 | 5 | нет (из прошлого прогона) |
| stml_rust_p3.json | 12:26 | 0 | да |
| stml_s5_load.json | 10:57 | 90 | нет (из прошлого прогона) |
| supervisor_measure.json | 12:27 | 0 | да |
| t1055_coverage.json | 12:26 | 0 | да |
| wdac_audit.json | 18:37 | 1070 | нет (из прошлого прогона) |
| wdac_inventory.json | 20:02 | 984 | нет (из прошлого прогона) |
| windows_defender.json | 12:24 | 3 | да |
| windows_e2e.json | 12:24 | 3 | да |

## Что доказано измерением
- Надёжностная платформа: R2/R3/R6/R8/R9/R10 — см. stage1 и chaos-отчёты.
- Контракты v3.0 и capability negotiation — контрактные тесты, drift-check.
- Детекция на реальных событиях: Linux eBPF exec/LSM/net, Windows System/Defender.
- Обратимые действия: suspend/resume, карантин с AES-GCM и восстановлением.
- Shadow ML: ONNX-инференс с подписанным ModelPack (fail-closed).
- IPC: JSON-RPC с ролями, замеры задержки и отказов.

## Что НЕ доказано (и почему)
- R1/R4 (доступность/сессии): нужен многочасовой soak, а не 3-минутный прогон.
- E7 (TPR@FPR): цель не достигнута — измерено 0,86 @1 % FPR; нужен ансамбль/данные.
- E11 как эффективность: матрица покрытия — полнота отображения, не red-team.
- E12: enforce L0 требует elevation и 2 недель audit (блокер D).
- Драйвер/ядро: нет подписи и WDK (блокеры A/B), спайк 5 не закрыт.
- Linux Secure Boot/fapolicyd: нет таргета (блокер C).

## Блокеры, требующие человека
A) EV-сертификат + Hardware Dev Center (подпись драйвера).
B) Windows тест-VM с WDK/testsigning. C) Linux-VM с Secure Boot/fapolicyd.
D) Окно с admin (RTP, WDAC audit, ETW-TI). E) rustup — закрыт (Rust-порт F19 сделан).

