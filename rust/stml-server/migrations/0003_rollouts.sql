-- P2: approvals tenant column + rollouts.

ALTER TABLE approvals ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS rollouts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT '',
    policy_id TEXT NOT NULL,
    version TEXT NOT NULL,
    percent INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS rollout_agents (
    rollout_id BIGINT NOT NULL,
    agent_id UUID NOT NULL,
    old_version TEXT,
    PRIMARY KEY (rollout_id, agent_id)
);
