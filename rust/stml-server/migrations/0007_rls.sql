-- P5: tenant RLS for PostgreSQL (defense in depth).
-- The server sets `app.tenant_id` per pooled connection (STML_TENANT).
-- FORCE RLS applies even to the table owner; keep the app role non-superuser.

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agents_tenant ON agents;
CREATE POLICY agents_tenant ON agents
    USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reports_tenant ON reports;
CREATE POLICY reports_tenant ON reports
    USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS policies_tenant ON policies;
CREATE POLICY policies_tenant ON policies
    USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS approvals_tenant ON approvals;
CREATE POLICY approvals_tenant ON approvals
    USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollouts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rollouts_tenant ON rollouts;
CREATE POLICY rollouts_tenant ON rollouts
    USING (tenant_id = current_setting('app.tenant_id', true));
