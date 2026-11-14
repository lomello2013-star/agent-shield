# PostgreSQL: RLS, backup, restore

## RLS

Migration `rust/stml-server/migrations/0007_rls.sql`:

- `FORCE ROW LEVEL SECURITY` on `agents`, `reports`, `policies`, `approvals`, `rollouts`.
- Policy: `tenant_id = current_setting('app.tenant_id', true)`.
- Rust sets `app.tenant_id` on every pooled connection from `STML_TENANT`
  (default `default`). One tenant per server instance; multi-tenant needs
  per-request pools or a proxy.
- Apply only after the server version that sets `app.tenant_id` is deployed;
  otherwise queries return zero rows.

Test (two agents, tenants `t` and `default`):
- `STML_TENANT=t` → only `tenant-t`;
- `STML_TENANT=default` → only `tenant-default`.

## Backup

```powershell
.\scripts\stml_pg_backup.ps1 -Database stml_p4 -Password <pw>
```

Creates `artifacts/pg-backups/<db>-<stamp>.dump` + `.sha256`.

## Restore

Create an empty target DB first (role needs CREATEDB, or DBA does it), then:

```powershell
.\scripts\stml_pg_restore.ps1 -File <dump> -Database stml_p4_restore -Password <pw>
```

`-CreateDatabase` exists but requires CREATEDB; normal `stml` role does not have it.

## Not covered

- HA/failover, PITR/WAL archiving, retention policy, off-site copies.
- Production HSM/KMS for DB credentials.
