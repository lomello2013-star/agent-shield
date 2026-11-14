# Server completeness and external gates

This file is the honest boundary between what the repository can finish and what
needs infrastructure/people outside it.

## Implemented / testable

| Area | State |
|---|---|
| Python STML server | Fleet, reports, policies, approvals, rollouts, audit, GUI, metrics, SLO |
| Rust/axum server | Agents, enrolment, heartbeat/inventory/reports, policies, approvals, rollouts, trust, CRL, models, cases, audit verify |
| PostgreSQL | RLS, backup/restore scripts, migration; HA/PITR runbook |
| Auth | Role tokens, Ed25519 body signatures, mTLS + CRL |
| Agent → connector | JSONL reports, spool, retries, signed enrol, commands |
| Linux auditd | Collector/parser/e2e tests, deb package, systemd unit |
| Agent panel | Localhost live panel: health, collectors, verdicts, confirmations |
| Updates | Signed A/B bundles, health rollback, CLI |
| Docker/Helm | Python image, compose, chart with probes/RWO safety; not end-to-end deployed here |
| NATS | Adapter placeholder; local bus is the supported mode |
| Tauri | Not built; the local panel covers the agent UI need |

## Not implemented (requires external resources)

| Item | Why blocked |
|---|---|
| Independent penetration test | Needs an external tester and a defined scope |
| EDR vendor stand / kernel driver certification | Microsoft/EDR partner process, signing portal |
| Commercial code-signing certificate | Certificate authority + legal identity |
| PostgreSQL HA/failover | Second host, quorum (Patroni/etcd), VIP/pgBouncer |
| Off-site immutable backup | Object storage account + retention policy |
| HSM/quorum for policy key | YubiHSM/HSM or institutional quorum |
| DPIA/legal review | Organization/legal owner |
| NATS/Kafka production bus | Broker cluster, auth, monitoring |
| Tauri signed installers | Node/Tauri toolchain + platform signing |

## Rust/Python parity gaps

Rust intentionally covers the durable server surface. Python additionally has:

- `/metrics` (Prometheus)
- `/v0/slo`
- `/v0/incidents`
- `/v0/modules`
- `/v0/ops`
- `/v0/audit/export`
- richer GUI dashboard

These are read-only operational endpoints. Add them to Rust only with a
migration plan; do not silently fork the API shape.

## NATS mode

`stml/server/bus.py` has `LocalBus` and a fail-closed `NatsBus` placeholder. The
server refuses to start with `event_bus=nats` until a broker is configured; this
is deliberate. A production adapter must add: connection retry, subject naming,
tenant isolation, auth/TLS, and a dead-letter policy.

## Docker/Helm caveat

The chart defaults to **one replica** because the Python server uses SQLite on a
ReadWriteOnce volume. Running two replicas against SQLite corrupts state. For
HA, use PostgreSQL + the Rust server or an external managed database, and split
the deployment.

## Definition of done for production

- independent pen-test report closed;
- restore/PITR drill on a second host;
- signed installers and update channel;
- HSM-backed policy/update keys;
- DPIA and operator runbooks;
- alerting/SLO on-call ownership.
