# stml-server (Rust/axum scaffold)

> Reference Python server remains authoritative. This is the production-stack
> scaffold with PostgreSQL; API parity is not complete.

## Build / run

```powershell
$env:DATABASE_URL="postgres://stml:stml@127.0.0.1:5432/stml"
$env:STML_BIND="127.0.0.1:8080"
cargo run --features postgres
```

- `GET /health` → `{ok, db: "ok"|"not_configured"|"error"}`
- `GET /v0/agents` → rows from PostgreSQL (read-only, no auth yet)

## Database

- PostgreSQL 16, dev DB `stml`, role `stml`/`stml` (localhost only; **not production**).
- Migration: `psql -h 127.0.0.1 -U stml -d stml -f migrations/0001_init.sql`
- Tables: agents, reports, policies, approvals.

## Status

- `cargo check --features postgres` ✅
- `cargo build --features postgres` ✅
- `/health` DB probe ✅
- `/v0/agents` query ✅ (manual test row)
- auth/Ed25519/enrol/heartbeat/reports/policies/trust/learning ❌ (P1+)
