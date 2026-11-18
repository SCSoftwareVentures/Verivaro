BEGIN;
CREATE ROLE verivaro_portability_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
SET LOCAL ROLE verivaro_owner;
GRANT USAGE ON SCHEMA vv_api TO verivaro_portability_operator;
-- No runtime or HTTP access to raw storage locations. Operator must quiesce the
-- tenant before copying originals. Every project digest must have an actual audited
-- export by the same still-authorised tenant/project owner.
CREATE FUNCTION vv_api.portability_original_inventory(t uuid,i uuid,expected jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;cnt integer;item jsonb;pr uuid;sha text;objects jsonb;
BEGIN
 IF t IS NULL OR i IS NULL OR expected IS NULL OR jsonb_typeof(expected)<>'array' OR jsonb_array_length(expected) NOT BETWEEN 1 AND 20 OR octet_length(expected::text)>16384 THEN RAISE EXCEPTION 'invalid export inventory' USING ERRCODE='22023';END IF;
 LOCK TABLE vv_app.project,vv_private.project_member,vv_private.membership,vv_private.privacy_export_audit,vv_app.quarantine_receipt,vv_private.file_reservation IN SHARE MODE;
 SELECT count(*) INTO cnt FROM vv_app.project WHERE tenant_id=t;
 IF cnt<>jsonb_array_length(expected) OR (SELECT count(DISTINCT x->>'projectId') FROM jsonb_array_elements(expected)x)<>cnt THEN RAISE EXCEPTION 'incomplete project inventory' USING ERRCODE='42501';END IF;
 FOR item IN SELECT x FROM jsonb_array_elements(expected)x LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR NOT (item ? 'projectId' AND item ? 'sha256') OR item->>'sha256' IS NULL OR item->>'sha256'!~'^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid export entry' USING ERRCODE='22023';END IF;
  pr:=(item->>'projectId')::uuid;sha:=item->>'sha256';
  IF a IS NULL THEN SELECT actor_id INTO a FROM vv_private.privacy_export_audit WHERE tenant_id=t AND project_id=pr AND id=i AND sha256=sha;END IF;
  IF a IS NULL OR NOT EXISTS(SELECT 1 FROM vv_private.privacy_export_audit f JOIN vv_app.project p ON (p.tenant_id,p.id)=(f.tenant_id,f.project_id) JOIN vv_private.project_member pm ON (pm.tenant_id,pm.project_id,pm.actor_id)=(f.tenant_id,f.project_id,f.actor_id) JOIN vv_private.membership m ON (m.tenant_id,m.actor_id)=(pm.tenant_id,pm.actor_id) WHERE f.tenant_id=t AND f.project_id=pr AND f.id=i AND f.sha256=sha AND f.actor_id=a AND pm.active AND pm.role='owner' AND m.active AND m.tenant_role='owner') THEN RAISE EXCEPTION 'audited current owner export required' USING ERRCODE='42501';END IF;
 END LOOP;
 IF (SELECT count(*) FROM vv_app.quarantine_receipt WHERE tenant_id=t)>4000 THEN RAISE EXCEPTION 'original inventory limit' USING ERRCODE='54000';END IF;
 IF EXISTS(SELECT 1 FROM vv_app.quarantine_receipt q JOIN vv_private.file_reservation f ON f.object_key=q.object_key WHERE q.tenant_id=t AND (q.tenant_id,q.project_id,q.intent_id)<>(f.tenant_id,f.project_id,f.intent_id)) THEN RAISE EXCEPTION 'storage scope mismatch' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('projectId',q.project_id,'intentId',q.intent_id,'objectKey',q.object_key,'sha256',q.actual_sha256,'bytes',q.actual_bytes,'mediaType',q.media_type) ORDER BY q.project_id,q.intent_id),'[]'::jsonb) INTO objects FROM vv_app.quarantine_receipt q WHERE q.tenant_id=t;
 RETURN jsonb_build_object('tenantId',t,'exportId',i,'objects',objects,'projectCount',cnt);
END $$;
REVOKE ALL ON FUNCTION vv_api.portability_original_inventory(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.portability_original_inventory(uuid,uuid,jsonb) TO verivaro_portability_operator;
RESET ROLE;
COMMIT;
