BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE OR REPLACE FUNCTION vv_api.catalog(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;docs jsonb;reqs jsonb;drafts jsonb;role_name text;releases jsonb:='[]'::jsonb;
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
 SELECT role INTO role_name FROM vv_private.project_member WHERE tenant_id=t AND project_id=p AND actor_id=a AND active;
 IF role_name='owner' THEN
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',r.id,'draftId',r.draft_id,'generation',r.generation::text,'current',coalesce(g.generation=r.generation AND g.confirmed_generation=g.generation,false),
 'documentVersionIds',(SELECT jsonb_agg(z->>'documentVersionId' ORDER BY z->>'documentVersionId') FROM jsonb_array_elements(r.payload::jsonb->'documents') z),
 'originalDocumentVersionIds',coalesce((SELECT jsonb_agg(o.document_version_id ORDER BY o.document_version_id) FROM vv_app.original_release o WHERE o.tenant_id=t AND o.project_id=p AND o.release_id=r.id),'[]'::jsonb),
 'grants',coalesce((SELECT jsonb_agg(jsonb_build_object('id',i.id,'expiresAt',i.expires_at,'revoked',i.revoked_at IS NOT NULL,'originalAccess',i.original_access,'expired',i.expires_at<=clock_timestamp()) ORDER BY i.created_at DESC,i.id) FROM vv_private.index_grant i WHERE i.tenant_id=t AND i.project_id=p AND i.release_id=r.id),'[]'::jsonb)) ORDER BY r.approved_at DESC,r.id),'[]'::jsonb) INTO releases
 FROM vv_app.index_release r LEFT JOIN vv_app.scope_checkpoint g ON (g.tenant_id,g.project_id)=(r.tenant_id,r.project_id) WHERE r.tenant_id=t AND r.project_id=p;
 END IF;
 RETURN jsonb_build_object('documents',docs,'requirements',reqs,'drafts',drafts,'role',role_name,'actorId',a,'releases',releases);
END $$;
REVOKE ALL ON FUNCTION vv_api.catalog(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.catalog(uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
