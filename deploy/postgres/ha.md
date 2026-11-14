# PostgreSQL HA / PITR runbook

This is the production-shaped path for STML. It is intentionally split into
**local, testable** steps and **external** operations (a second node, object
storage, a failover manager).

## 1. Primary configuration

`postgresql.conf` (PostgreSQL 16):

```conf
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
wal_keep_size = 1GB
archive_mode = on
archive_command = 'test ! -f /srv/pg-wal/%f && cp %p /srv/pg-wal/%f'
archive_timeout = 300
hot_standby = on
```

`pg_hba.conf` on the primary:

```conf
# replication from the standby host only
host replication replicator 10.0.0.12/32 scram-sha-256
```

Create the role:

```sql
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '...';
```

Reload/restart, then verify:

```sql
SHOW wal_level;          -- replica
SELECT * FROM pg_stat_archiver;
```

`/srv/pg-wal` must be on durable storage and must never be overwritten. In
production use pgBackRest/Barman instead of a raw `cp` directory.

## 2. Standby (streaming replication)

On the standby host:

```bash
pg_basebackup -h 10.0.0.11 -U replicator -D /var/lib/postgresql/16/main \
  -Fp -Xs -P -R
```

`-R` writes `primary_conninfo` and creates `standby.signal`. Start PostgreSQL:

```bash
systemctl start postgresql
psql -c "SELECT status, sender_host, write_lag, flush_lag FROM pg_stat_replication;"
```

The standby is read-only until promotion.

## 3. Promotion / failover

Manual, controlled promotion:

```bash
pg_ctl promote -D /var/lib/postgresql/16/main
```

Then point the application at the new primary (DNS/VIP/pgBouncer).  
Automated failover requires an external quorum manager:

- Patroni + etcd/Consul (recommended for self-hosted);
- pg_auto_failover;
- cloud managed PostgreSQL.

**Do not** run two primaries without a fence/quorum. STML does not implement
leader election itself.

## 4. PITR

Base backup:

```bash
pg_basebackup -h 10.0.0.11 -U replicator -D /srv/base/2026-11-15 -Fp -Xs -P
```

Restore to a new directory:

```bash
cp -a /srv/base/2026-11-15 /var/lib/postgresql/16/restore
cat > /var/lib/postgresql/16/restore/postgresql.auto.conf <<'EOF'
restore_command = 'cp /srv/pg-wal/%f %p'
recovery_target_time = '2026-11-15 12:00:00+00'
recovery_target_action = 'promote'
EOF
touch /var/lib/postgresql/16/restore/recovery.signal
pg_ctl -D /var/lib/postgresql/16/restore start
```

Verify the target time, then run the normal STML migrations/health checks.

## 5. Local backup/restore (already scripted)

```powershell
.\scripts\stml_pg_backup.ps1 -Database stml_p4 -Password <pw>
.\scripts\stml_pg_restore.ps1 -File <dump> -Database stml_p4_restore -Password <pw>
```

Restore into an **empty** database; the `stml` role has no CREATEDB.

## 6. Acceptance tests

- [ ] `pg_stat_archiver.failed_count = 0`.
- [ ] standby `pg_stat_replication` has `streaming`.
- [ ] `pg_basebackup` restore starts.
- [ ] PITR restores to a timestamp before a known change.
- [ ] promotion makes the standby writable.
- [ ] application reconnect/failover tested with pgBouncer/VIP.
- [ ] backup + WAL are off-host and immutable/versioned.

## 7. External blockers

- second host / quorum (etcd/Consul);
- off-site object storage with retention/immutability;
- production DB credentials in a KMS/HSM;
- independent restore drill.
