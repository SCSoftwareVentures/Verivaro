BEGIN;
CREATE ROLE verivaro_capability NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
SET LOCAL ROLE verivaro_owner;
GRANT USAGE ON SCHEMA vv_api TO verivaro_capability;
REVOKE EXECUTE ON FUNCTION vv_api.read_shared_index(uuid,text) FROM verivaro_runtime;
GRANT EXECUTE ON FUNCTION vv_api.read_shared_index(uuid,text) TO verivaro_capability;
ALTER TABLE vv_private.index_grant ADD COLUMN original_access boolean NOT NULL DEFAULT false;
CREATE TABLE vv_app.original_release(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,release_id uuid NOT NULL,
 document_version_id uuid NOT NULL,approved_by uuid NOT NULL,approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,release_id,document_version_id),
 FOREIGN KEY(tenant_id,project_id,release_id) REFERENCES vv_app.index_release(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,document_version_id) REFERENCES vv_app.document_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,approved_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_private.capability_audit(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,grant_id uuid NOT NULL REFERENCES vv_private.index_grant(id),
 document_version_id uuid NOT NULL,action text NOT NULL CHECK(action='original-authorised-after-rescan'),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $$ DECLARE rel regclass;BEGIN
 FOREACH rel IN ARRAY ARRAY['vv_app.original_release'::regclass,'vv_private.capability_audit'::regclass] LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',rel);EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',rel);EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING(true) WITH CHECK(true)',rel);END LOOP;
END $$;
-- Approval is a one-time immutable additional allowlist, separate from index approval.
CREATE FUNCTION vv_api.approve_originals(t uuid,p uuid,r uuid,selected uuid[]) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;rel vv_app.index_release%ROWTYPE;existing uuid[];wanted uuid[];
BEGIN a:=vv_private.release_owner(t,p);
 IF selected IS NULL OR cardinality(selected) NOT BETWEEN 1 AND 50 OR array_position(selected,NULL) IS NOT NULL OR cardinality(selected)<>(SELECT count(DISTINCT x) FROM unnest(selected) x) THEN RAISE EXCEPTION 'invalid selection' USING ERRCODE='22023';END IF;
 SELECT ir.* INTO rel FROM vv_app.index_release ir JOIN vv_app.scope_checkpoint g ON (g.tenant_id,g.project_id)=(ir.tenant_id,ir.project_id)
 WHERE ir.tenant_id=t AND ir.project_id=p AND ir.id=r AND ir.generation=g.generation AND g.confirmed_generation=g.generation;
 IF NOT FOUND THEN RAISE EXCEPTION 'release unavailable' USING ERRCODE='42501';END IF;
 SELECT array_agg(x ORDER BY x) INTO wanted FROM unnest(selected) x;
 SELECT array_agg(document_version_id ORDER BY document_version_id) INTO existing FROM vv_app.original_release WHERE tenant_id=t AND project_id=p AND release_id=r;
 IF existing IS NOT NULL THEN IF existing=wanted THEN RETURN r;END IF;RAISE EXCEPTION 'original selection frozen' USING ERRCODE='23505';END IF;
 IF EXISTS(SELECT 1 FROM unnest(wanted) x WHERE NOT EXISTS(
 SELECT 1 FROM jsonb_array_elements(rel.payload::jsonb->'documents') z
 JOIN vv_app.version_origin o ON o.tenant_id=t AND o.project_id=p AND o.version_id=(z->>'documentVersionId')::uuid
 JOIN vv_app.quarantine_receipt q ON (q.tenant_id,q.project_id,q.intent_id)=(o.tenant_id,o.project_id,o.intent_id)
 WHERE o.version_id=x AND q.actual_bytes<=10485760 AND q.actual_sha256=z->>'originalSha256'
 AND EXISTS(SELECT 1 FROM vv_app.scan_attempt sa WHERE sa.tenant_id=t AND sa.project_id=p AND sa.intent_id=q.intent_id AND sa.scanned_sha256=q.actual_sha256 AND sa.outcome='clean')
 AND NOT EXISTS(SELECT 1 FROM vv_app.scan_attempt sa WHERE sa.tenant_id=t AND sa.project_id=p AND sa.intent_id=q.intent_id AND sa.outcome='rejected')
 )) THEN RAISE EXCEPTION 'original unavailable' USING ERRCODE='42501';END IF;
 INSERT INTO vv_app.original_release(tenant_id,project_id,release_id,document_version_id,approved_by) SELECT t,p,r,x,a FROM unnest(wanted) x;
 RETURN r;
END $$;
CREATE FUNCTION vv_api.grant_originals(t uuid,p uuid,r uuid,i uuid,secret_digest text,ttl integer) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_api AS $$
BEGIN
 PERFORM vv_private.release_owner(t,p);
 IF NOT EXISTS(SELECT 1 FROM vv_app.original_release WHERE tenant_id=t AND project_id=p AND release_id=r) THEN RAISE EXCEPTION 'original approval required' USING ERRCODE='42501';END IF;
 PERFORM vv_api.grant_index(t,p,r,i,secret_digest,ttl);
 UPDATE vv_private.index_grant SET original_access=true WHERE id=i AND tenant_id=t AND project_id=p;
 RETURN i;
END $$;
CREATE FUNCTION vv_api.read_original(r uuid,v uuid,secret_digest text,audit boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE gr vv_private.index_grant%ROWTYPE; out jsonb;
BEGIN
 IF secret_digest IS NULL OR secret_digest!~'^[0-9a-f]{64}$' OR audit IS NULL THEN RAISE EXCEPTION 'original unavailable' USING ERRCODE='42501';END IF;
 -- First resolve grant, lock project before grant row, matching owner revoke ordering.
 SELECT * INTO gr FROM vv_private.index_grant WHERE token_hash=secret_digest AND release_id=r AND original_access;
 IF NOT FOUND THEN RAISE EXCEPTION 'original unavailable' USING ERRCODE='42501';END IF;
 PERFORM 1 FROM vv_app.project WHERE tenant_id=gr.tenant_id AND id=gr.project_id FOR SHARE;
 SELECT * INTO gr FROM vv_private.index_grant WHERE id=gr.id AND token_hash=secret_digest AND release_id=r AND original_access AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'original unavailable' USING ERRCODE='42501';END IF;
 SELECT jsonb_build_object('objectKey',q.object_key,'sha256',q.actual_sha256,'bytes',q.actual_bytes,'mediaType',q.media_type,'state','quarantined') INTO out
 FROM vv_app.original_release o JOIN vv_app.index_release ir ON (ir.tenant_id,ir.project_id,ir.id)=(o.tenant_id,o.project_id,o.release_id)
 JOIN vv_app.scope_checkpoint g ON (g.tenant_id,g.project_id)=(o.tenant_id,o.project_id)
 JOIN vv_app.document_version d ON (d.tenant_id,d.project_id,d.id)=(o.tenant_id,o.project_id,o.document_version_id)
 JOIN vv_app.version_origin vo ON (vo.tenant_id,vo.project_id,vo.version_id)=(d.tenant_id,d.project_id,d.id)
 JOIN vv_app.quarantine_receipt q ON (q.tenant_id,q.project_id,q.intent_id)=(vo.tenant_id,vo.project_id,vo.intent_id)
 WHERE o.tenant_id=gr.tenant_id AND o.project_id=gr.project_id AND o.release_id=r AND o.document_version_id=v
 AND ir.generation=g.generation AND g.confirmed_generation=g.generation AND d.reviewed_by IS NOT NULL AND d.scan_state='clean'
 AND NOT EXISTS(SELECT 1 FROM vv_app.document_version n WHERE n.tenant_id=d.tenant_id AND n.project_id=d.project_id AND n.document_id=d.document_id AND n.revision>d.revision)
 AND q.actual_sha256=d.content_sha256 AND q.actual_bytes<=10485760
 AND EXISTS(SELECT 1 FROM vv_app.scan_attempt sa WHERE sa.tenant_id=q.tenant_id AND sa.project_id=q.project_id AND sa.intent_id=q.intent_id AND sa.scanned_sha256=q.actual_sha256 AND sa.outcome='clean')
 AND NOT EXISTS(SELECT 1 FROM vv_app.scan_attempt sa WHERE sa.tenant_id=q.tenant_id AND sa.project_id=q.project_id AND sa.intent_id=q.intent_id AND sa.outcome='rejected');
 IF out IS NULL THEN RAISE EXCEPTION 'original unavailable' USING ERRCODE='42501';END IF;
 IF audit THEN INSERT INTO vv_private.capability_audit(grant_id,document_version_id,action) VALUES(gr.id,v,'original-authorised-after-rescan');END IF;
 RETURN out;
END $$;
CREATE FUNCTION vv_api.read_bundle_index(r uuid,secret_digest text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto,vv_api AS $$
DECLARE base jsonb;body text;items jsonb;
BEGIN
 base:=vv_api.read_shared_index(r,secret_digest);
 SELECT jsonb_agg(o.document_version_id ORDER BY o.document_version_id) INTO items
 FROM vv_private.index_grant gr JOIN vv_app.original_release o ON (o.tenant_id,o.project_id,o.release_id)=(gr.tenant_id,gr.project_id,gr.release_id)
 WHERE gr.token_hash=secret_digest AND gr.release_id=r AND gr.original_access AND gr.revoked_at IS NULL AND gr.expires_at>clock_timestamp();
 IF items IS NULL THEN RAISE EXCEPTION 'bundle unavailable' USING ERRCODE='42501';END IF;
 body:=jsonb_build_object('schema','verivaro-original-selection-v1','index',base->>'json','indexSha256',base->>'sha256','originalDocumentVersionIds',items)::text;
 RETURN jsonb_build_object('json',body,'sha256',encode(vv_crypto.digest(convert_to(body,'UTF8'),'sha256'),'hex'));
END $$;
REVOKE ALL ON FUNCTION vv_api.approve_originals(uuid,uuid,uuid,uuid[]),vv_api.grant_originals(uuid,uuid,uuid,uuid,text,integer),vv_api.read_original(uuid,uuid,text,boolean),vv_api.read_bundle_index(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.approve_originals(uuid,uuid,uuid,uuid[]),vv_api.grant_originals(uuid,uuid,uuid,uuid,text,integer) TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION vv_api.read_original(uuid,uuid,text,boolean),vv_api.read_bundle_index(uuid,text) TO verivaro_capability;
RESET ROLE;
COMMIT;
