-- Verivaro G1 foundation, PostgreSQL 15+. Apply as migration owner, not runtime role.
BEGIN;
CREATE SCHEMA IF NOT EXISTS verivaro;
CREATE TABLE verivaro.tenants (
  id uuid PRIMARY KEY, name text NOT NULL CHECK (length(trim(name)) > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE verivaro.projects (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES verivaro.tenants(id),
  name text NOT NULL CHECK (length(trim(name)) > 0),
  UNIQUE (tenant_id, id)
);
CREATE TABLE verivaro.memberships (
  tenant_id uuid NOT NULL REFERENCES verivaro.tenants(id),
  actor_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('owner','reviewer','contributor','viewer')),
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, actor_id)
);
CREATE TABLE verivaro.evidence (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL,
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  storage_ref text NOT NULL CHECK (length(trim(storage_ref)) > 0),
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, project_id) REFERENCES verivaro.projects(tenant_id,id)
);
-- A runtime connection must set both values with set_config(..., true)
-- inside an explicit transaction. Never use session-level SET.
CREATE FUNCTION verivaro.authorized(scope uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, verivaro
AS $$
 SELECT scope::text = NULLIF(current_setting('verivaro.tenant_id', true), '')
 AND EXISTS (
   SELECT 1 FROM verivaro.memberships m
   WHERE m.tenant_id = scope AND m.actor_id::text =
     NULLIF(current_setting('verivaro.actor_id', true), '')
     AND m.revoked_at IS NULL
 )
$$;
ALTER TABLE verivaro.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE verivaro.projects FORCE ROW LEVEL SECURITY;
CREATE POLICY projects_scope ON verivaro.projects
 USING (verivaro.authorized(tenant_id))
 WITH CHECK (verivaro.authorized(tenant_id));
ALTER TABLE verivaro.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE verivaro.evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_scope ON verivaro.evidence
 USING (verivaro.authorized(tenant_id))
 WITH CHECK (verivaro.authorized(tenant_id));
-- Membership lookup policy must not recursively call authorized().
ALTER TABLE verivaro.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE verivaro.memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY membership_self ON verivaro.memberships
 USING (tenant_id::text = NULLIF(current_setting('verivaro.tenant_id',true),'')
        AND actor_id::text = NULLIF(current_setting('verivaro.actor_id',true),'')
        AND revoked_at IS NULL);
-- The membership self-policy above supports only self-visibility; management
-- requires a separately reviewed privileged workflow.
ALTER TABLE verivaro.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE verivaro.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_scope ON verivaro.tenants
 USING (verivaro.authorized(id));
-- Explicit grants are required for a dedicated non-owner, non-BYPASSRLS runtime role.
-- Do not grant TRUNCATE, REFERENCES, or schema ownership to runtime.
COMMIT;
