BEGIN;
CREATE INDEX evidence_scope_order ON verivaro.evidence(tenant_id,project_id,id);
-- The old RLS path repeatedly evaluated nested membership/context checks per
-- row, causing a statement timeout even on the small CI data set. Authorize
-- exactly once per statement, then perform an indexed bounded metadata read.
-- Retain forced RLS and its policy for all direct table access.
CREATE FUNCTION verivaro_ingestion.list_evidence_metadata(t uuid,p uuid)
RETURNS TABLE(id uuid,project_id uuid,sha256 text,created_by uuid,created_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $list$
DECLARE c text[];a uuid;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR t IS NULL OR p IS NULL THEN RETURN;END IF;
 c:=verivaro.bound_context();
 IF c IS NULL OR c[1]<>t::text THEN RETURN;END IF;
 a:=c[2]::uuid;
 IF EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=a)
 OR NOT EXISTS(SELECT 1 FROM verivaro.memberships m JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id
 WHERE m.tenant_id=t AND m.actor_id=a AND m.revoked_at IS NULL AND pm.project_id=p AND pm.revoked_at IS NULL AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp()))
 THEN RETURN;END IF;
 RETURN QUERY SELECT e.id,e.project_id,e.sha256,e.created_by,e.created_at FROM verivaro.evidence e WHERE e.tenant_id=t AND e.project_id=p ORDER BY e.id LIMIT 200;
END $list$;
REVOKE ALL ON FUNCTION verivaro_ingestion.list_evidence_metadata(uuid,uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_ingestion TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION verivaro_ingestion.list_evidence_metadata(uuid,uuid) TO verivaro_runtime;
COMMIT;
