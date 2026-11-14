# SLO и наблюдаемость STML (S6)

## 1. Эндпоинты

| Эндпоинт | Доступ | Назначение |
|---|---|---|
| `/health` | открыт (loopback) | живость |
| `/metrics` | admin | Prometheus text |
| `/v0/slo` | admin | snapshot: stats, audit_ok, bus_events, targets |
| `/v0/audit/export` | admin | JSON/CEF |

## 2. Метрики Prometheus

`stml_agents{status=healthy|degraded|offline|isolated}`, `stml_reports_total`,
`stml_reports_p0_total`, `stml_approvals_pending`, `stml_models_total`,
`stml_uptime_seconds`.

## 3. SLO (MVP)

| SLO | Цель | Источник |
|---|---|---|
| Доступность | 99,5 % → 99,9 % | `/health` watchdog |
| Heartbeat p95 | ≤2 с | нагрузочный тест |
| P0 потери | 0 | outbox/ACK |
| Approval SLA | 48 ч | очередь |
| Audit verify | 100 % | `/v0/audit/verify` |

## 4. Watchdog — три линии

1. **Внутренний** `/health` + `/v0/slo` (`scripts/stml_watchdog.py`).
2. **2a Prometheus** — scrape `/metrics`, **отдельный хост**.
3. **2b SIEM** — audit export.
4. **3 внешний** — облачный uptime или локальный независимый пробер (air-gapped, другая ВМ).

Правило: линия 2a — отдельный хост; иначе независимость фиктивна. Air-gapped:
если пробер недоступен >1 ч → оператор on-call выполняет ручной чек-лист и
пишет в audit.

## 5. Инциденты

Runbook: `docs/runbook-stml.md`. Backup/restore: `python -m stml.server backup|restore`.
