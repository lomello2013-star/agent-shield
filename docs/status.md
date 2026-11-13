# Статус проекта «ИИ-защитник» (user-mode)

> Сгенерировано `scripts/run_all.py` — 2026-11-13 20:35 UTC. Не редактировать вручную.

## Регрессионный прогон

| Шаг | Результат | Детали |
|---|---|---|
| tests | ok | 451 passed in 8.18s |
| rules_and_coverage | ok | rules=28 lint=0 detection=100.0% prevention=100.0% |
| schema_drift | ok | in sync |
| immutable_policy | ok | fingerprint=d8ae913401ea contract=ok |
| artifacts | ok | present=39/39 |
| windows_system_e2e | ok | events=60 verdicts=60 |
| windows_defender_e2e | ok | events=200 verdicts=1 before_classification=200 |
| windows_chaos | ok | final_verdicts=80 loss=0 |
| linux_exec_e2e | ok | exit=0 |
| linux_lsm_e2e | ok | exit=0 |
| linux_net_e2e | ok | exit=0 |
| linux_mem_e2e | ok | exit=0 |
| linux_ptrace_e2e | ok | exit=0 |
| linux_procmem_e2e | ok | exit=0 |
| linux_mprotect_e2e | ok | exit=0 |
| linux_corr_e2e | ok | exit=0 |
| linux_tree_e2e | ok | exit=0 |
| linux_tree_fp | ok | exit=0 |
| linux_provenance | ok | exit=0 |
| gen_docs | ok | exit=0 bytes=513 |
| f04_r2_margin | ok | exit=0 (no json artefact read) |
| f02_f03_signal_levels | ok | exit=0 bytes=2873 |
| f01_confidence_gap | ok | exit=0 (no json artefact read) stderr=[0;93m2026-11-13 23:35:52.3472433 [W:onnxruntime:, execution_frame.cc:913 onnxruntime::ExecutionFrame::VerifyOutputSize |
| f09_ppv_target | ok | exit=0 bytes=1601 |
| f12_behavioral | ok | exit=0 bytes=2623 |
| f13_scenarios | ok | exit=0 bytes=2502 |
| supervisor_measure | ok | exit=0 bytes=1133 |
| final_summary | ok | exit=0 bytes=7266 |
| docs_consistency | ok | exit=0 bytes=1597 |

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
| Linux exec: ядро→вердикт p95 | 0.31 мс | linux_e2e |
| Linux LSM: чтений→вердиктов | 200 / 200 | linux_lsm |
| Linux net: C2-портов→вердиктов | 200 / 200 | linux_net |
| Windows System: событий→вердиктов | 60 / 60 | windows_e2e |
| Windows Defender: событий→вердиктов | 200 / 1 | windows_defender |
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
| Champion / challenger | None / v2 ΔTPR 2.61 п.п. | registry |
| Совпадение алертов v1↔v2 | 96.02 % | registry |
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
| F05: ppid в exec/LSM/net | 200 / 200 / 400 | linux_* |
| F10: FBR на holdout (звучащая политика) | 13.3333 % (цель 10), покрытие 86.6667 % | stage2 |
| F09: PPV на пороге алерта | 0.5642 при FPR 0.00052 (TPR 0.67242) | f09 |
| F12: поведенческий TPR / benign-алерты | 1.0 / 0 | f12 |
| F13: сценарии E1–E5 (detect/prevent) | 9 / 9 из 10 | f13 |
| Супервизор: перезапуск после kill | медиана 273.0 мс, цепочка True (12 записей) | supervisor |
| Доступность под супервизором | 100.0 % за 3600.2 с, перезапусков 0 | soak_supervised |

## Свежесть артефактов

| Артефакт | Изменён (UTC) | Возраст, мин | В этом прогоне |
|---|---|---|---|
| audit_bench.json | 12:36 | 1920 | нет (из прошлого прогона) |
| calibration_report.json | 17:48 | 1607 | нет (из прошлого прогона) |
| challenger_report.json | 17:58 | 1597 | нет (из прошлого прогона) |
| chaos_report.json | 12:34 | 1921 | нет (из прошлого прогона) |
| devlog_audit.json | 20:35 | 0 | да |
| disagreement_report.json | 13:47 | 1848 | нет (из прошлого прогона) |
| docker_matrix.json | 12:53 | 1903 | нет (из прошлого прогона) |
| docs_consistency.json | 20:35 | 0 | да |
| ensemble_report.json | 13:49 | 1847 | нет (из прошлого прогона) |
| etwti_t1055.json | 18:33 | 122 | нет (из прошлого прогона) |
| f01_confidence.json | 20:35 | 0 | да |
| f02_f03_measure.json | 20:35 | 0 | да |
| f04_r2_margin.json | 20:35 | 0 | да |
| f08_tail.json | 18:59 | 1536 | нет (из прошлого прогона) |
| f09_ppv_target.json | 20:35 | 0 | да |
| f11_bisect.json | 19:40 | 1496 | нет (из прошлого прогона) |
| f11_controls.json | 00:46 | 1190 | нет (из прошлого прогона) |
| f11_health_livelock.json | 19:11 | 1524 | нет (из прошлого прогона) |
| f11_health_probe_1500.json | 19:11 | 1524 | нет (из прошлого прогона) |
| f11_health_probe_summary.json | 19:11 | 1524 | нет (из прошлого прогона) |
| f11_pydantic_focus.json | 22:56 | 1299 | нет (из прошлого прогона) |
| f11_pydantic_stress.json | 21:07 | 1409 | нет (из прошлого прогона) |
| f11_repeat.json | 00:10 | 1226 | нет (из прошлого прогона) |
| f12_behavioral.json | 20:35 | 0 | да |
| f13_scenarios.json | 20:35 | 0 | да |
| final_summary.json | 20:35 | 0 | да |
| gate_report.json | 12:31 | 1924 | нет (из прошлого прогона) |
| gen_docs.json | 20:35 | 0 | да |
| ipc_report.json | 12:44 | 1911 | нет (из прошлого прогона) |
| linux_corr.json | 20:35 | 1 | да |
| linux_e2e.json | 20:33 | 2 | да |
| linux_load.json | 12:53 | 1903 | нет (из прошлого прогона) |
| linux_lsm.json | 20:33 | 2 | да |
| linux_mem.json | 20:33 | 2 | да |
| linux_mprotect.json | 20:34 | 1 | да |
| linux_net.json | 20:33 | 2 | да |
| linux_procmem.json | 20:34 | 1 | да |
| linux_provenance.json | 20:35 | 0 | да |
| linux_ptrace.json | 20:34 | 2 | да |
| linux_tree.json | 20:35 | 1 | да |
| linux_tree_fp.json | 20:35 | 0 | да |
| pe_v2_report.json | 13:43 | 1853 | нет (из прошлого прогона) |
| release_engineering.json | 23:37 | 1258 | нет (из прошлого прогона) |
| report_metrics.json | 17:18 | 1637 | нет (из прошлого прогона) |
| run_all.json | 20:13 | 23 | нет (из прошлого прогона) |
| rust_bench.json | 23:20 | 1276 | нет (из прошлого прогона) |
| rust_gate.json | 23:26 | 1270 | нет (из прошлого прогона) |
| rust_ml_holdout_report.json | 22:23 | 1333 | нет (из прошлого прогона) |
| rust_ml_holdout_state.json | 22:23 | 1333 | нет (из прошлого прогона) |
| rust_port_slice1.json | 21:16 | 1399 | нет (из прошлого прогона) |
| rust_port_slice2.json | 21:29 | 1386 | нет (из прошлого прогона) |
| rust_port_slice3.json | 21:37 | 1378 | нет (из прошлого прогона) |
| rust_port_slice4.json | 21:42 | 1373 | нет (из прошлого прогона) |
| rust_port_slice5.json | 22:10 | 1345 | нет (из прошлого прогона) |
| rust_port_slice6.json | 22:18 | 1337 | нет (из прошлого прогона) |
| rust_port_slice7.json | 22:57 | 1299 | нет (из прошлого прогона) |
| rust_port_slice8.json | 23:26 | 1269 | нет (из прошлого прогона) |
| ship_v2.json | 13:43 | 1852 | нет (из прошлого прогона) |
| soak_6h_2026-11-13.json | 18:01 | 154 | нет (из прошлого прогона) |
| soak_before_hyperv_2026-11-13.json | 19:18 | 78 | нет (из прошлого прогона) |
| soak_before_reboot_2026-11-13.json | 18:47 | 109 | нет (из прошлого прогона) |
| soak_report.json | 11:50 | 526 | нет (из прошлого прогона) |
| soak_supervised.json | 11:13 | 563 | нет (из прошлого прогона) |
| soak_supervised_partial.json | 20:35 | 1 | да |
| stage11_report.json | 12:33 | 1923 | нет (из прошлого прогона) |
| stage12_chaos.json | 20:33 | 3 | да |
| stage1_report.json | 12:14 | 1942 | нет (из прошлого прогона) |
| stage2_report.json | 18:08 | 1587 | нет (из прошлого прогона) |
| stage4_report.json | 12:25 | 1931 | нет (из прошлого прогона) |
| stage5_report.json | 18:03 | 1593 | нет (из прошлого прогона) |
| stage7_report.json | 12:30 | 1926 | нет (из прошлого прогона) |
| stage8_report.json | 12:28 | 1928 | нет (из прошлого прогона) |
| supervisor_measure.json | 20:35 | 0 | да |
| t1055_coverage.json | 20:35 | 0 | да |
| wdac_audit.json | 18:37 | 119 | нет (из прошлого прогона) |
| wdac_inventory.json | 20:02 | 33 | нет (из прошлого прогона) |
| windows_defender.json | 20:32 | 3 | да |
| windows_e2e.json | 20:32 | 3 | да |

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

