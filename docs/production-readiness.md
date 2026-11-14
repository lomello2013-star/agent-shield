# STML — production readiness (честный статус)

> Дата: 2026-11-14. Это **reference MVP**, не production-релиз.
> Все этапы S0–S8 имеют работающий срез; часть production-гейтов не пройдена
> по внешним причинам (HSM, PostgreSQL, Rust/axum, Tauri, EDR-стенд, юрист).

## 1. Вердикт

| Уровень | Статус |
|---|---|
| Reference MVP (S0–S8 slices) | ✅ собран, 51 STML-тест + 16 IPC |
| Внутренний demo/pilot | ⚠️ возможен на SQLite + file-trust + web GUI |
| Production | ❌ не готов: HSM/quorum, PostgreSQL/HA, Rust/axum, Tauri, pen-test, DPIA, human-acceptance |

## 2. Гейты по этапам

| Этап | Работающий срез | Доказательство | Production-остаток | Гейт |
|---|---|---|---|---|
| **S0** | контракты, коннектор, ACL, подпись пакета, 5 RPC | 51 тест, `stml/tests/test_e2e.py`, signing tests | 4-VM стенд, human-подпись threat model | ✅ MVP |
| **S1** | fleet, enrolment, heartbeat, reports, GUI, TUI isolate, policy/rollout | `test_server_http.py`, `test_server_policy.py`, 1000-agent load | PostgreSQL, Rust/axum | ⚠️ partial |
| **S2** | file-Trust, approvals/SoD, keys, audit export, backup, mTLS | `test_trust.py`, `test_tls.py`, `test_backup.py` | prod HSM+quorum, CRL/OCSP, key ceremony с людьми | ⚠️ dev |
| **S3** | web GUI `/ui/` (Dashboard/Fleet/Policies/Approvals/Learning/Audit/Settings) | `stml/gui/index.html`, route test | Tauri, mTLS-клиент, Reports/Incidents/Modules/Ops, тренинг | ⚠️ partial |
| **S4** | telemetry/PII, cases, model registry, no-regression, activate/rollback | `test_learning.py` | песочница, реальный retrain, dual-slot на агенте, внешние советники, DPIA | ⚠️ partial |
| **S5** | LocalBus, 1000 агентов p95 111,6 мс, replay, offline | `artifacts/stml_s5_load.json` | реальный NATS/Kafka, push, 10k+ | ⚠️ partial |
| **S6** | `/metrics`, `/v0/slo`, watchdog, runbook, backup | `test_ops.py`, watchdog run `ok:true` | OTel, `windows_exporter`, pen-test, отдельный хост Prometheus | ⚠️ partial |
| **S7** | Dockerfile/Compose/Helm/systemd, DR-процедура | `deploy/`, `docs/deploy.md` | **runtime не проверен**: Docker daemon off, helm/кластер нет | ⚠️ manifests |
| **S8** | tenant-фильтрация, SIEM JSON/CEF, compat matrix | `test_tenant_isolation...`, `docs/compat.md` | реальные EDR-тесты, tenant-claim/RLS, per-tenant keys | ⚠️ partial |

## 3. Блокеры production

| # | Блокер | Почему не закрыт | Владелец |
|---|---|---|---|
| B1 | Production HSM + quorum (2-of-3) | нет YubiHSM/HSM-стенда | security engineer + PM |
| B2 | PostgreSQL/HA | PostgreSQL 16 установлен локально, dev-БД `stml` + миграция работают; **HA/RLS/parity/backup не сделаны** | DevOps |
| B3 | Rust/axum | P1–P5: agents/reports, policies/approvals/rollouts, trust/audit/learning, commands, `/ui/`, mTLS, 14 read checks, write parity, 1000 agents p95 145.9 ms; **CRL/Tauri/HA не сделаны** | Rust-инженер |
| B4 | Tauri + mTLS-клиент | нет Node/npm/Tauri toolchain | GUI-инженер |
| B5 | Реальный retrain/песочница | нет данных/GPU/песочницы; DPIA в финале | ML-инженер |
| B6 | Docker/Helm runtime | daemon не запущен, helm/кластер отсутствуют | DevOps |
| B7 | EDR/OS matrix | нет лицензий/стенда | PM |
| B8 | Pen-test + DPIA + human-acceptance | внешние люди/юрист | PM/юрист |

## 4. Что уже можно показывать

- `python -m stml.server run` → `/ui/`, `/health`, `/metrics`, `/v0/slo`.
- Коннектор: `python -m stml.connector run --server-url ...` → enrol/heartbeat/reports.
- Policy: подпись, dry-run, rollout/rollback, approvals SoD.
- Trust: ключи, отзыв/ротация, backup/restore.
- Learning: consent/PII, cases, model registry/regression.
- mTLS: сервер требует client cert.
- Rust/axum: **P1+P2+P3** — agents/reports, policies/rollouts, trust/audit/learning; PostgreSQL 16.
- 1000 агентов: p95 111,6 мс.

## 5. Критерий production-приёмки (не достигнут)

1. HSM/quorum + key ceremony + CRL/OCSP.
2. PostgreSQL + HA + backup/DR на целевом стенде.
3. Rust/axum (или письменное решение оставить Python) + pen-test.
4. Tauri/mTLS + тренинг оператора + S18/S19.
5. Реальный retrain + dual-slot на агенте + DPIA.
6. EDR/OS matrix + human-acceptance.

**До этого STML — демонстратор/пилот, не production.**
