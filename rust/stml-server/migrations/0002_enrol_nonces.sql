-- P1: enrolment tokens and replay nonces.

CREATE TABLE IF NOT EXISTS enrol_tokens (
    token TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    seen_at TIMESTAMPTZ NOT NULL
);
