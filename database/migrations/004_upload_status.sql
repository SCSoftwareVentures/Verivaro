BEGIN;
SET LOCAL ROLE verivaro_owner;
-- Only the intent's original actor (with current capture permission) may submit bytes.
-- Replaying a completed intent reveals status, never the private object key.
CREATE FUNCTION vv_api.upload_status(t uuid,p uuid,u uuid)
RETURNS TABLE(sha256 text,bytes bigint,media_type text,received boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;
BEGIN
 a:=vv_private.capture_actor(t,p);
 RETURN QUERY SELECT i.expected_sha256,i.expected_bytes,i.media_type,(r.intent_id IS NOT NULL)
 FROM vv_app.upload_intent i LEFT JOIN vv_app.quarantine_receipt r
 ON r.tenant_id=i.tenant_id AND r.project_id=i.project_id AND r.intent_id=i.id
 WHERE i.tenant_id=t AND i.project_id=p AND i.id=u AND i.created_by=a;
 IF NOT FOUND THEN RAISE EXCEPTION 'upload unavailable' USING ERRCODE='42501'; END IF;
END $$;
REVOKE ALL ON FUNCTION vv_api.upload_status(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.upload_status(uuid,uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
