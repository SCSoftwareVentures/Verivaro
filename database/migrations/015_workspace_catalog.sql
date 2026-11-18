BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE FUNCTION vv_api.catalog(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;docs jsonb;reqs jsonb;drafts jsonb;
BEGIN a:=vv_private.graph_lock(t,p);
 IF (SELECT count(*) FROM vv_app.document WHERE tenant_id=t AND project_id=p)>500 OR (SELECT count(*) FROM vv_app.upload_intent WHERE tenant_id=t AND project_id=p)>2000 THEN RAISE EXCEPTION 'catalog limit' USING ERRCODE='54000';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',d.id,'title',d.title,'currentVersionId',v.id,'revision',coalesce(v.revision,0),
 'uploads',coalesce((SELECT jsonb_agg(jsonb_build_object('id',i.id,'sha256',i.expected_sha256,'mediaType',i.media_type,'bytes',i.expected_bytes,'state',CASE WHEN vo.version_id IS NOT NULL THEN 'reviewed' WHEN x.state IS NOT NULL THEN 'extraction-'||x.state WHEN j.state IS NOT NULL THEN 'scan-'||j.state ELSE 'pending' END,'versionId',vo.version_id) ORDER BY i.created_at DESC,i.id)
 FROM vv_app.upload_intent i LEFT JOIN vv_private.scan_job j ON (j.tenant_id,j.project_id,j.intent_id)=(i.tenant_id,i.project_id,i.id)
 LEFT JOIN vv_private.extract_job x ON (x.tenant_id,x.project_id,x.intent_id)=(i.tenant_id,i.project_id,i.id)
 LEFT JOIN vv_app.version_origin vo ON (vo.tenant_id,vo.project_id,vo.intent_id)=(i.tenant_id,i.project_id,i.id)
 WHERE i.tenant_id=t AND i.project_id=p AND i.document_id=d.id),'[]'::jsonb)) ORDER BY d.created_at DESC,d.id),'[]'::jsonb) INTO docs
 FROM vv_app.document d LEFT JOIN LATERAL(SELECT dv.id,dv.revision FROM vv_app.document_version dv WHERE dv.tenant_id=t AND dv.project_id=p AND dv.document_id=d.id ORDER BY dv.revision DESC LIMIT 1)v ON true WHERE d.tenant_id=t AND d.project_id=p;
 WITH latest AS(SELECT DISTINCT ON(requirement_id) * FROM vv_app.requirement_version WHERE tenant_id=t AND project_id=p ORDER BY requirement_id,revision DESC)
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',r.requirement_id,'versionId',r.id,'revision',r.revision,'kind',r.criterion_kind,'expected',r.expected,'mandatory',r.mandatory) ORDER BY r.requirement_id),'[]'::jsonb) INTO reqs FROM latest r;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',h.id,'generation',h.generation::text,'createdAt',h.created_at,'stale',h.generation IS DISTINCT FROM g.generation OR h.scope_confirmed IS DISTINCT FROM coalesce(g.generation=g.confirmed_generation,false)) ORDER BY h.created_at DESC,h.id),'[]'::jsonb) INTO drafts FROM vv_app.handover_draft h LEFT JOIN vv_app.scope_checkpoint g ON (g.tenant_id,g.project_id)=(h.tenant_id,h.project_id) WHERE h.tenant_id=t AND h.project_id=p;
 RETURN jsonb_build_object('documents',docs,'requirements',reqs,'drafts',drafts);
END $$;
REVOKE ALL ON FUNCTION vv_api.catalog(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.catalog(uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
