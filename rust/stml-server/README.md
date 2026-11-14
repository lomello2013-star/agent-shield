# stml-server (Rust/axum + PostgreSQL), P2

> Python reference remains authoritative for the full API. This crate now covers
> P1 (agents/enrol/heartbeat/inventory/reports) and P2 (policies/rollouts/approvals).

## Build / run

```powershell
$env:DATABASE_URL="postgres://stml:stml@127.0.0.1:5432/stml_p2"
$env:STML_BIND="127.0.0.1:8080"
$env:STML_ADMIN_TOKEN="admin"
$env:STML_VIEWER_TOKEN="viewer"
$env:STML_APPROVER_TOKEN="approver"
$env:STML_POLICY_PUBKEY_FILE="C:\path\policy.pub"
cargo run
```

## Endpoints

| Method | Path | Auth |
|---|---|---|
| GET | `/health` | — |
| GET | `/v0/agents` | — |
| POST | `/v0/enrol` | one-time token |
| POST | `/v0/heartbeat` | Ed25519 |
| POST | `/v0/inventory` | Ed25519 |
| POST | `/v0/reports` | Ed25519 |
| GET | `/v0/policies` | viewer |
| POST | `/v0/policies` | admin + policy signature |
| GET | `/v0/approvals` | viewer |
| POST | `/v0/approvals/{id}/{approve|deny}` | approver |
| POST | `/v0/rollouts` | admin + approved policy |
| GET | `/v0/rollouts/{id}` | viewer |
| POST | `/v0/rollouts/{id}/{promote|halt|rollback}` | admin |

## Status (P2)

- Policy signature verified (Ed25519, `key_id`, canonical JSON).
- Approval required before rollout; **Admin cannot approve** (SoD), **Approver cannot rollout**.
- Rollout 1→10→50→100, promote/halt/rollback; tenant-scoped.
- **Not yet:** trust/keys/CRL, learning, mTLS, RLS, HA, HTTP 201 parity (returns 200).
