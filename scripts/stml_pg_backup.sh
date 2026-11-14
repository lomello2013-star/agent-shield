#!/usr/bin/env bash
# STML PostgreSQL backup/restore (custom format).
set -euo pipefail
DB="${1:-stml}"
OUT="${2:-artifacts/pg-backups}"
USER_DB="${PGUSER:-stml}"
HOST="${PGHOST:-127.0.0.1}"
PORT="${PGPORT:-5432}"
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
FILE="$OUT/$DB-$STAMP.dump"
pg_dump -h "$HOST" -p "$PORT" -U "$USER_DB" -Fc -f "$FILE" "$DB"
sha256sum "$FILE" > "$FILE.sha256"
echo "backup=$FILE"
