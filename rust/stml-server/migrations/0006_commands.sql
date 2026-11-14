-- P4/B: agent command queue (Rust parity).

CREATE TABLE IF NOT EXISTS commands (
    command_id UUID PRIMARY KEY,
    agent_id UUID NOT NULL,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    acked_at TIMESTAMPTZ,
    result JSONB
);
