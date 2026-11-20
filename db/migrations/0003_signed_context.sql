-- G1: replace untrusted UUID GUCs with an authenticated, backend/transaction-bound context.
-- Apply as migration administrator. The runtime must never own the verification key.
BEGIN;
CREATE SCHEMA verivaro_private;
REVOKE ALL ON SCHEMA verivaro_private FROM PUBLIC;
CREATE EXTENSION pgcrypto WITH SCHEMA verivaro_private;
CREATE TABLE verivaro_private.context_key (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  key_bytes bytea NOT NULL CHECK (octet_length(key_bytes) = 32)
);
REVOKE ALL ON verivaro_private.context_key FROM PUBLIC;

-- Canonical envelope: v1|tenant UUID|actor UUID|backend PID|xid8|expiry epoch|hex HMAC.
-- Key provisioned out of band; missing key, malformed envelope or unbound transaction denies access.
CREATE FUNCTION verivaro.bound_context() RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, verivaro_private
AS $$
DECLARE raw text; parts text[]; payload text; k bytea; expected bytea; now_epoch bigint;
BEGIN
  raw := current_setting('verivaro.signed_context', true);
  IF raw IS NULL OR length(raw) > 200 OR raw !~ '^v1[|][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[|][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[|][1-9][0-9]{0,9}[|][1-9][0-9]{0,19}[|][1-9][0-9]{0,11}[|][0-9a-f]{64}$' THEN
    RETURN NULL;
  END IF;
  parts := string_to_array(raw, '|');
  IF parts[4] IS DISTINCT FROM pg_backend_pid()::text
     OR parts[5] IS DISTINCT FROM pg_current_xact_id_if_assigned()::text THEN RETURN NULL; END IF;
  now_epoch := floor(extract(epoch FROM statement_timestamp()))::bigint;
  IF parts[6]::bigint <= now_epoch OR parts[6]::bigint > now_epoch + 60 THEN RETURN NULL; END IF;
  SELECT key_bytes INTO k FROM verivaro_private.context_key WHERE singleton;
  IF k IS NULL THEN RETURN NULL; END IF;
  payload := array_to_string(parts[1:6], '|');
  expected := verivaro_private.hmac(convert_to(payload, 'UTF8'), k, 'sha256');
  -- Double HMAC prevents a caller from choosing a comparison prefix.
  IF verivaro_private.hmac(decode(parts[7], 'hex'), k, 'sha256')
     IS DISTINCT FROM verivaro_private.hmac(expected, k, 'sha256') THEN RETURN NULL; END IF;
  RETURN ARRAY[parts[2], parts[3]];
END $$;
REVOKE ALL ON FUNCTION verivaro.bound_context() FROM PUBLIC;
CREATE OR REPLACE FUNCTION verivaro.authorized(scope uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, verivaro
AS $$
 SELECT COALESCE(scope::text = (verivaro.bound_context())[1] AND EXISTS (
   SELECT 1 FROM verivaro.memberships m
   WHERE m.tenant_id = scope AND m.actor_id::text = (verivaro.bound_context())[2]
     AND m.revoked_at IS NULL
 ), false)
$$;
ALTER POLICY membership_self ON verivaro.memberships
 USING (tenant_id::text = (verivaro.bound_context())[1]
        AND actor_id::text = (verivaro.bound_context())[2] AND revoked_at IS NULL);
ALTER POLICY evidence_actor_insert ON verivaro.evidence
 WITH CHECK (created_by::text = (verivaro.bound_context())[2]
   AND EXISTS (SELECT 1 FROM verivaro.memberships m WHERE m.tenant_id = evidence.tenant_id
     AND m.actor_id = evidence.created_by AND m.revoked_at IS NULL
     AND m.role IN ('owner','reviewer','contributor')));
COMMIT;
