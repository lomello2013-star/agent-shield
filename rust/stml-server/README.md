# stml-server (Rust/axum + PostgreSQL), P1

> Python reference remains authoritative for the full API. This crate now covers
> the P1 read/write core against PostgreSQL.

## Build / run

```powershell
$env:DATABASE_URL="postgres://stml:stml@127.0.0.1:5432/stml"
$env:STML_BIND="127.0.0.1:8080"
cargo run
```

## Endpoints

- `GET /health` → DB probe
- `GET /v0/agents` → registry
- `POST /v0/enrol` → one-time token + Ed25519 PEM pubkey
- `POST /v0/heartbeat` → signed body (`X-STML-Signature`, base64)
- `POST /v0/inventory` → signed body
- `POST /v0/reports` → `{reports:[...]}`, idempotent by `report_id`

## Database

- PostgreSQL 16, dev DB `stml`, role `stml`/`stml` (localhost only; **not production**).
- Migrations: `psql ... -f migrations/0001_init.sql`, `0002_enrol_nonces.sql`.
- Tables: agents, reports, policies, approvals, enrol_tokens, nonces.

## Status (P1)

- `cargo check` / `cargo build` ✅
- Enrol + signed heartbeat/inventory/reports + `/v0/agents` ✅ (Python-generated Ed25519 test)
- **Not yet:** operator auth/Z, policies/rollouts/approvals (P2), trust/learning, mTLS, RLS, HA.
- Replay protection by `nonce`; timestamp skew check — TODO.
