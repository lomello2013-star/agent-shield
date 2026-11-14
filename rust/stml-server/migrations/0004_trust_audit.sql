-- P3: trust keys, CRL-lite, audit hash chain.

CREATE TABLE IF NOT EXISTS keys (
    key_id TEXT PRIMARY KEY,
    key_class TEXT NOT NULL,
    public_hex TEXT NOT NULL,
    private_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    rotated_from TEXT
);

CREATE TABLE IF NOT EXISTS revoked_certs (
    serial TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id BIGSERIAL PRIMARY KEY,
    ts_micros BIGINT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
