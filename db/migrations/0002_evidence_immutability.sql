-- G1 hardening, additive to 0001. Must be applied by migration owner.
BEGIN;
-- The runtime role must never own these tables or hold BYPASSRLS.
-- Protect evidence history against UPDATE/DELETE even if a future policy is broad.
CREATE FUNCTION verivaro.reject_evidence_mutation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'evidence records are append-only' USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER evidence_immutable
  BEFORE UPDATE OR DELETE ON verivaro.evidence
  FOR EACH ROW EXECUTE FUNCTION verivaro.reject_evidence_mutation();
-- Only the active actor can create an evidence record.
-- This policy is restrictive, combining with the existing tenant scope policy.
CREATE POLICY evidence_actor_insert ON verivaro.evidence
  AS RESTRICTIVE FOR INSERT
  WITH CHECK (
    created_by::text = NULLIF(current_setting('verivaro.actor_id',true),'')
    AND EXISTS (
      SELECT 1 FROM verivaro.memberships m
      WHERE m.tenant_id = evidence.tenant_id
        AND m.actor_id = evidence.created_by
        AND m.revoked_at IS NULL
        AND m.role IN ('owner','reviewer','contributor')
    )
  );
-- A runtime identity is not authorised to rewrite a project's tenant.
CREATE FUNCTION verivaro.reject_project_reparent() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
    RAISE EXCEPTION 'project tenant cannot change' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER project_tenant_fixed
  BEFORE UPDATE ON verivaro.projects
  FOR EACH ROW EXECUTE FUNCTION verivaro.reject_project_reparent();
COMMIT;
