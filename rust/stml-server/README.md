# stml-server (Rust/axum + PostgreSQL), P3

> Python reference remains authoritative for the full API. This crate covers
> P1 (agents/reports), P2 (policies/rollouts/approvals) and P3 (trust/learning).

## Build / run

```powershell
$env:DATABASE_URL="postgres://stml:stml@127.0.0.1:5432/stml_p3"
$env:STML_BIND="127.0.0.1:8080"
$env:STML_ADMIN_TOKEN="admin"
$env:STML_VIEWER_TOKEN="viewer"
$env:STML_APPROVER_TOKEN="approver"
$env:STML_POLICY_PUBKEY_FILE="C:\path\policy.pub"
$env:STML_TRUST_DIR="C:\path\trust"
cargo run
```

## Endpoints

| Method | Path | Auth |
|---|---|---|
| GET | `/health` | — |
| GET | `/v0/agents` | — |
| POST | `/v0/enrol` | one-time token |
| POST | `/v0/heartbeat` `/v0/inventory` `/v0/reports` | Ed25519 |
| GET/POST | `/v0/policies` | viewer / admin |
| POST | `/v0/agents/{id}/isolate` | admin |
| POST | `/v0/commands/ack` | Ed25519 |
| GET/POST | `/v0/approvals`; POST `{id}/{approve|deny}` | viewer / approver |
| POST | `/v0/rollouts`; GET `{id}`; POST `{id}/{promote|halt|rollback}` | admin/viewer |
| GET/POST | `/v0/trust/keys`; POST `{id}/{revoke|rotate}` | viewer/admin |
| POST | `/v0/tls/revoke`; GET `/v0/tls/revoked` | admin |
| GET | `/v0/audit/verify` | admin |
| POST | `/v0/telemetry` | admin, consent required |
| GET/POST | `/v0/cases` | viewer/admin |
| GET/POST | `/v0/models`; POST `/v0/models/{id}/{activate|regress}`; POST `/v0/models/rollback` | viewer/admin |

## Status

- P1: enrol, signed heartbeat/inventory/reports, agents.
- P2: policy signature, approvals+SoD, rollout 1→10→50→100, rollback.
- P3: trust keys (Ed25519, private hex in trust dir), CRL-lite, audit hash chain,
  opt-in telemetry (PII keys stripped), cases, model registry + no-regression + rollback.
- Commands: `isolate` / approval `confirm` → queue → heartbeat `commands` → signed ack.
- **Not yet:** P4 mTLS/Tauri/GUI, P5 contract parity, RLS/HA, timestamp skew,
  HTTP 201 parity, HSM.
