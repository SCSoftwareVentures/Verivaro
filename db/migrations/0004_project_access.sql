-- G1 forward-only: explicit project assignment, actor emergency disable, least privilege.
BEGIN;
CREATE TABLE verivaro_private.disabled_actors(
 actor_id uuid PRIMARY KEY, disabled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.disabled_actors FROM PUBLIC;
CREATE FUNCTION verivaro.active_identity() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private
AS $$
 SELECT COALESCE((verivaro.bound_context())[2] IS NOT NULL
  AND current_setting('transaction_isolation')='read committed'
  AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors
    WHERE actor_id::text=(verivaro.bound_context())[2]),false)
$$;
REVOKE ALL ON FUNCTION verivaro.active_identity() FROM PUBLIC;
ALTER POLICY membership_self ON verivaro.memberships
 USING (verivaro.active_identity() AND tenant_id::text=(verivaro.bound_context())[1]
 AND actor_id::text=(verivaro.bound_context())[2] AND revoked_at IS NULL);
CREATE TABLE verivaro.project_members(
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, actor_id uuid NOT NULL,
 role text NOT NULL CHECK(role IN ('owner','reviewer','contributor','viewer')),
 expires_at timestamptz, revoked_at timestamptz,
 PRIMARY KEY(tenant_id,project_id,actor_id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES verivaro.memberships(tenant_id,actor_id)
);
ALTER TABLE verivaro.project_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE verivaro.project_members FORCE ROW LEVEL SECURITY;
CREATE POLICY project_member_self ON verivaro.project_members
 USING(verivaro.authorized(tenant_id)
 AND actor_id::text=(verivaro.bound_context())[2]
 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>statement_timestamp()));
CREATE FUNCTION verivaro.project_access(t uuid,p uuid,operation text) RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,verivaro
AS $$
 SELECT EXISTS(
 SELECT 1 FROM verivaro.project_members pm JOIN verivaro.memberships m
 ON m.tenant_id=pm.tenant_id AND m.actor_id=pm.actor_id
 WHERE pm.tenant_id=t AND pm.project_id=p
 AND pm.actor_id::text=(verivaro.bound_context())[2]
 AND CASE operation
 WHEN 'read' THEN true
 WHEN 'contribute' THEN pm.role IN ('owner','reviewer','contributor') AND m.role IN ('owner','reviewer','contributor')
 WHEN 'review' THEN pm.role IN ('owner','reviewer') AND m.role IN ('owner','reviewer')
 WHEN 'manage' THEN pm.role='owner' AND m.role='owner'
 ELSE false END)
$$;
ALTER POLICY projects_scope ON verivaro.projects
 USING(verivaro.project_access(tenant_id,id,'read'))
 WITH CHECK(verivaro.project_access(tenant_id,id,'manage'));
ALTER POLICY evidence_scope ON verivaro.evidence
 USING(verivaro.project_access(tenant_id,project_id,'read'))
 WITH CHECK(verivaro.project_access(tenant_id,project_id,'contribute'));
-- Explicit group role, no shipped credentials. A separate deployment provisions login.
CREATE ROLE verivaro_runtime NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
REVOKE ALL ON SCHEMA verivaro FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA verivaro FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA verivaro FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro TO verivaro_runtime;
GRANT SELECT ON verivaro.tenants,verivaro.memberships,verivaro.projects,verivaro.project_members,verivaro.evidence TO verivaro_runtime;
GRANT INSERT ON verivaro.evidence TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION verivaro.bound_context(),verivaro.active_identity(),
 verivaro.authorized(uuid),verivaro.project_access(uuid,uuid,text) TO verivaro_runtime;
COMMIT;
