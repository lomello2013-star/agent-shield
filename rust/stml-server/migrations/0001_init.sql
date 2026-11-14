-- STML PostgreSQL schema (draft for the Rust/axum port).
-- Kept close to stml/server/store.py; final migration happens with the adapter.

CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    arch TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    status TEXT NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL,
    isolated BOOLEAN NOT NULL DEFAULT FALSE,
    policy_version TEXT,
    pubkey TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id BIGSERIAL PRIMARY KEY,
    report_id TEXT UNIQUE NOT NULL,
    tenant_id TEXT NOT NULL,
    agent_id UUID NOT NULL,
    priority TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    ack_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS policies (
    tenant_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    version TEXT NOT NULL,
    channel TEXT NOT NULL,
    content JSONB NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, policy_id, version)
);

CREATE TABLE IF NOT EXISTS approvals (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    payload JSONB NOT NULL,
    proposed_by TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    decided_by TEXT,
    decided_at TIMESTAMPTZ
);
