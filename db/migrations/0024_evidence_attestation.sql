BEGIN;
CREATE ROLE verivaro_evidence_auditor NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA verivaro_ingestion TO verivaro_evidence_auditor;
-- Only identifiers and cryptographic commitments cross the audit boundary.
-- The evidence bytes and raw storage references never leave this function.
CREATE FUNCTION verivaro_ingestion.attestation_inventory()
RETURNS TABLE(id uuid,digest text,encrypted boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $inventory$
BEGIN
 IF (SELECT count(*) FROM verivaro.evidence)>4096 THEN RAISE EXCEPTION 'attestation capacity exceeded'; END IF;
 IF EXISTS(
 SELECT 1 FROM verivaro.evidence e LEFT JOIN verivaro_private.evidence_objects o ON o.evidence_id=e.id
 WHERE (e.storage_ref='db-encrypted-v1') IS DISTINCT FROM (o.evidence_id IS NOT NULL)
 OR (o.evidence_id IS NOT NULL AND (o.tenant_id<>e.tenant_id OR o.project_id<>e.project_id OR o.actor_id<>e.created_by OR o.sha256<>e.sha256
 OR o.cipher_digest<>verivaro_private.digest(o.envelope,'sha256') OR octet_length(o.envelope)<>o.bytes+28))
 ) THEN RAISE EXCEPTION 'evidence integrity mismatch'; END IF;
 RETURN QUERY SELECT e.id,
 encode(verivaro_private.digest(convert_to(jsonb_build_array(
 'vv-custody-record-v1',e.id,e.tenant_id,e.project_id,e.sha256,
 encode(verivaro_private.digest(convert_to(e.storage_ref,'UTF8'),'sha256'),'hex'),
 e.created_by,to_char(e.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 CASE WHEN o.evidence_id IS NULL THEN NULL ELSE jsonb_build_array(
 o.session_id,o.request_id,o.bytes,o.key_id,o.media_type,encode(o.cipher_digest,'hex'),o.scan_policy,
 to_char(o.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) END
 )::text,'UTF8'),'sha256'),'hex'),o.evidence_id IS NOT NULL
 FROM verivaro.evidence e LEFT JOIN verivaro_private.evidence_objects o ON o.evidence_id=e.id ORDER BY e.id;
END $inventory$;
REVOKE ALL ON FUNCTION verivaro_ingestion.attestation_inventory() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_ingestion.attestation_inventory() TO verivaro_evidence_auditor;
COMMIT;
