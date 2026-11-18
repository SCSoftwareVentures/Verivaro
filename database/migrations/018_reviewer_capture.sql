BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.reviewer_original_audit(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,tenant_id uuid NOT NULL,project_id uuid NOT NULL,intent_id uuid NOT NULL,actor_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_app.upload_intent(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,actor_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_app.milestone_capture(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,intent_id uuid NOT NULL,milestone_id uuid NOT NULL,milestone_revision integer NOT NULL,
 actor_id uuid NOT NULL,registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,intent_id),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_app.upload_intent(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,milestone_id,milestone_revision) REFERENCES vv_app.prooflock_revision(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,actor_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
DO $$ DECLARE rel regclass;BEGIN
 FOREACH rel IN ARRAY ARRAY['vv_app.reviewer_original_audit'::regclass,'vv_app.milestone_capture'::regclass] LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',rel);EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',rel);EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING(true) WITH CHECK(true)',rel);END LOOP;
END $$;
CREATE FUNCTION vv_api.reviewer_original(t uuid,p uuid,u uuid,audit boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;out jsonb;
BEGIN a:=vv_private.graph_lock(t,p);
 IF audit IS NULL THEN RAISE EXCEPTION 'invalid audit' USING ERRCODE='22023';END IF;
 SELECT jsonb_build_object('objectKey',q.object_key,'sha256',q.actual_sha256,'bytes',q.actual_bytes,'mediaType',q.media_type,'state','quarantined') INTO out
 FROM vv_app.quarantine_receipt q WHERE q.tenant_id=t AND q.project_id=p AND q.intent_id=u AND q.actual_bytes<=10485760
 AND EXISTS(SELECT 1 FROM vv_app.scan_attempt s WHERE s.tenant_id=t AND s.project_id=p AND s.intent_id=u AND s.scanned_sha256=q.actual_sha256 AND s.outcome='clean')
 AND NOT EXISTS(SELECT 1 FROM vv_app.scan_attempt s WHERE s.tenant_id=t AND s.project_id=p AND s.intent_id=u AND s.outcome='rejected');
 IF out IS NULL THEN RAISE EXCEPTION 'original unavailable' USING ERRCODE='42501';END IF;
 IF audit THEN INSERT INTO vv_app.reviewer_original_audit(tenant_id,project_id,intent_id,actor_id) VALUES(t,p,u,a);END IF;
 RETURN out;
END $$;
-- QR is a non-secret pointer only. Caller must authenticate and have project capture authority.
CREATE FUNCTION vv_api.request_milestone_upload(t uuid,p uuid,d uuid,u uuid,sha text,n bigint,mime text,m uuid,rev integer) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;inserted uuid;previous vv_app.upload_intent%ROWTYPE;link vv_app.milestone_capture%ROWTYPE;
BEGIN a:=vv_private.capture_actor(t,p);
 PERFORM 1 FROM vv_app.project WHERE tenant_id=t AND id=p FOR UPDATE;
 IF u IS NULL OR d IS NULL OR m IS NULL OR rev IS NULL OR rev<1 OR sha IS NULL OR sha!~'^[0-9a-f]{64}$' OR n IS NULL OR n NOT BETWEEN 1 AND 52428800 OR mime IS NULL OR mime NOT IN ('application/pdf','image/jpeg','image/png','text/plain') THEN RAISE EXCEPTION 'invalid capture' USING ERRCODE='22023';END IF;
 SELECT * INTO previous FROM vv_app.upload_intent WHERE tenant_id=t AND project_id=p AND id=u;
 IF FOUND THEN
  SELECT * INTO link FROM vv_app.milestone_capture WHERE tenant_id=t AND project_id=p AND intent_id=u;
  IF link.intent_id IS NOT NULL AND (previous.created_by,previous.document_id,previous.expected_sha256,previous.expected_bytes,previous.media_type,link.milestone_id,link.milestone_revision,link.actor_id) IS NOT DISTINCT FROM (a,d,sha,n,mime,m,rev,a) THEN RETURN u;END IF;
  RAISE EXCEPTION 'capture conflict' USING ERRCODE='23505';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM vv_app.document WHERE tenant_id=t AND project_id=p AND id=d) OR NOT EXISTS(SELECT 1 FROM vv_app.prooflock_revision x WHERE x.tenant_id=t AND x.project_id=p AND x.id=m AND x.revision=rev AND vv_private.current_requirement(t,p,x.requirement_version_id) AND NOT EXISTS(SELECT 1 FROM vv_app.prooflock_revision y WHERE y.tenant_id=t AND y.project_id=p AND y.id=m AND y.revision>rev)) THEN RAISE EXCEPTION 'milestone unavailable or stale' USING ERRCODE='42501';END IF;
 INSERT INTO vv_app.upload_intent(tenant_id,project_id,id,document_id,expected_sha256,expected_bytes,media_type,created_by) VALUES(t,p,u,d,sha,n,mime,a) ON CONFLICT DO NOTHING RETURNING id INTO inserted;
 IF inserted IS NULL THEN RAISE EXCEPTION 'capture conflict' USING ERRCODE='23505';END IF;
 INSERT INTO vv_app.milestone_capture(tenant_id,project_id,intent_id,milestone_id,milestone_revision,actor_id) VALUES(t,p,u,m,rev,a);
 RETURN u;
END $$;
REVOKE ALL ON FUNCTION vv_api.reviewer_original(uuid,uuid,uuid,boolean),vv_api.request_milestone_upload(uuid,uuid,uuid,uuid,text,bigint,text,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.reviewer_original(uuid,uuid,uuid,boolean),vv_api.request_milestone_upload(uuid,uuid,uuid,uuid,text,bigint,text,uuid,integer) TO verivaro_runtime;
CREATE OR REPLACE FUNCTION vv_api.catalog(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;docs jsonb;reqs jsonb;drafts jsonb;role_name text;releases jsonb:='[]'::jsonb;
BEGIN a:=vv_private.graph_lock(t,p);
 IF (SELECT count(*) FROM vv_app.document WHERE tenant_id=t AND project_id=p)>500 OR (SELECT count(*) FROM vv_app.upload_intent WHERE tenant_id=t AND project_id=p)>2000 THEN RAISE EXCEPTION 'catalog limit' USING ERRCODE='54000';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',d.id,'title',d.title,'currentVersionId',v.id,'revision',coalesce(v.revision,0),
 'uploads',coalesce((SELECT jsonb_agg(jsonb_build_object('id',i.id,'sha256',i.expected_sha256,'mediaType',i.media_type,'bytes',i.expected_bytes,'state',CASE WHEN vo.version_id IS NOT NULL THEN 'reviewed' WHEN x.state IS NOT NULL THEN 'extraction-'||x.state WHEN j.state IS NOT NULL THEN 'scan-'||j.state ELSE 'pending' END,'versionId',vo.version_id,'milestoneId',mc.milestone_id,'milestoneRevision',mc.milestone_revision) ORDER BY i.created_at DESC,i.id)
 FROM vv_app.upload_intent i LEFT JOIN vv_app.milestone_capture mc ON (mc.tenant_id,mc.project_id,mc.intent_id)=(i.tenant_id,i.project_id,i.id) LEFT JOIN vv_private.scan_job j ON (j.tenant_id,j.project_id,j.intent_id)=(i.tenant_id,i.project_id,i.id)
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
RESET ROLE;
COMMIT;
