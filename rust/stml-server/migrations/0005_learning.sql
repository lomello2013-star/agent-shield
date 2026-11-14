-- P3 learning: telemetry, cases, model registry.

CREATE TABLE IF NOT EXISTS telemetry (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    consent BOOLEAN NOT NULL,
    events JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    report_id TEXT,
    label TEXT NOT NULL,
    holdout BOOLEAN NOT NULL DEFAULT FALSE,
    features JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS models (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    metrics JSONB NOT NULL,
    signature TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS model_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    active_id BIGINT,
    previous_id BIGINT
);

INSERT INTO model_state(id) VALUES (1) ON CONFLICT DO NOTHING;
