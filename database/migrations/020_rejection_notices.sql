BEGIN;
SET LOCAL ROLE verivaro_owner;
-- An immutable objection is separate from a correctable case and remains visible after resolution.
CREATE TABLE vv_app.rejection_notice(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,source_span_id uuid NOT NULL,
 document_version_id uuid NOT NULL,original_sha256 text NOT NULL CHECK(original_sha256 ~ '^[0-9a-f]{64}$'),
 page integer NOT NULL CHECK(page BETWEEN 1 AND 20),lo integer NOT NULL CHECK(lo>=0),hi integer NOT NULL CHECK(hi>lo AND hi-lo<=2000),
 page_sha256 text NOT NULL CHECK(page_sha256 ~ '^[0-9a-f]{64}$'),created_by uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),UNIQUE(tenant_id,project_id,original_sha256,page,lo,hi,page_sha256),
 FOREIGN KEY(tenant_id,project_id,source_span_id) REFERENCES vv_app.source_span(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,document_version_id) REFERENCES vv_app.document_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
ALTER TABLE vv_app.rejection_notice ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_app.rejection_notice FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_app.rejection_notice TO verivaro_owner USING(true) WITH CHECK(true);
CREATE FUNCTION vv_api.import_rejection_notice(t uuid,p uuid,i uuid,s uuid,v uuid,pg integer,lo_cp integer,hi_cp integer,q text,digest text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.rejection_notice%ROWTYPE;d vv_app.document_version%ROWTYPE;page_row vv_app.version_page%ROWTYPE;duplicate_id uuid;
BEGIN
 a:=vv_private.graph_lock(t,p);
 IF i IS NULL OR s IS NULL OR v IS NULL OR pg IS NULL OR pg NOT BETWEEN 1 AND 20 OR lo_cp IS NULL OR hi_cp IS NULL OR lo_cp<0 OR hi_cp<=lo_cp OR hi_cp-lo_cp>2000 OR q IS NULL OR length(trim(q))=0 OR length(q)<>hi_cp-lo_cp OR digest IS NULL OR digest !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid notice' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.rejection_notice WHERE tenant_id=t AND project_id=p AND id=i;
 IF FOUND THEN
 IF (old.source_span_id,old.document_version_id,old.page,old.lo,old.hi,old.page_sha256,old.created_by) IS NOT DISTINCT FROM (s,v,pg,lo_cp,hi_cp,digest,a) AND EXISTS(SELECT 1 FROM vv_app.source_span ss WHERE ss.tenant_id=t AND ss.project_id=p AND ss.id=s AND ss.quote=q) THEN RETURN i;END IF;
 RAISE EXCEPTION 'notice conflict' USING ERRCODE='23505';END IF;
 IF EXISTS(SELECT 1 FROM vv_app.rejection_event WHERE tenant_id=t AND project_id=p AND id=i) THEN RAISE EXCEPTION 'case identifier collision' USING ERRCODE='23505';END IF;
 IF NOT vv_private.current_document(t,p,v) THEN RAISE EXCEPTION 'reviewed notice unavailable' USING ERRCODE='42501';END IF;
 SELECT * INTO d FROM vv_app.document_version WHERE tenant_id=t AND project_id=p AND id=v;
 SELECT * INTO page_row FROM vv_app.version_page WHERE tenant_id=t AND project_id=p AND version_id=v AND page=pg;
 IF NOT FOUND OR digest IS DISTINCT FROM page_row.text_sha256 OR hi_cp>page_row.length_cp OR substring(d.extracted_text FROM page_row.start_cp+lo_cp+1 FOR hi_cp-lo_cp) IS DISTINCT FROM q THEN RAISE EXCEPTION 'notice source mismatch' USING ERRCODE='22023';END IF;
 SELECT n.id INTO duplicate_id FROM vv_app.rejection_notice n WHERE n.tenant_id=t AND n.project_id=p AND (n.original_sha256,n.page,n.lo,n.hi,n.page_sha256)=(d.content_sha256,pg,lo_cp,hi_cp,digest);
 IF FOUND THEN RETURN duplicate_id;END IF;
 IF (SELECT count(*) FROM vv_app.rejection_notice WHERE tenant_id=t AND project_id=p)>=500 THEN RAISE EXCEPTION 'notice quota' USING ERRCODE='54000';END IF;
 PERFORM vv_private.add_graph_span(t,p,s,v,pg,lo_cp,hi_cp,q,digest,a);
 INSERT INTO vv_app.rejection_notice(tenant_id,project_id,id,source_span_id,document_version_id,original_sha256,page,lo,hi,page_sha256,created_by) VALUES(t,p,i,s,v,d.content_sha256,pg,lo_cp,hi_cp,digest,a);
 PERFORM vv_private.bump_graph(t,p);RETURN i;
END $$;
CREATE FUNCTION vv_private.rejection_notices(t uuid,p uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',n.id,'documentVersionId',n.document_version_id,'originalSha256',n.original_sha256,'page',n.page,'start',n.lo,'end',n.hi,'textSha256',n.page_sha256,'quote',s.quote,'current',vv_private.current_document(t,p,n.document_version_id),
 'history',coalesce((SELECT jsonb_agg(jsonb_build_object('revision',e.revision,'requirementVersionId',e.requirement_version_id,'state',e.state,'note',e.note,'reviewerId',e.reviewer_id,'recordedAt',e.recorded_at) ORDER BY e.revision) FROM vv_app.rejection_event e WHERE e.tenant_id=t AND e.project_id=p AND e.id=n.id),'[]'::jsonb)) ORDER BY n.id),'[]'::jsonb)
 FROM vv_app.rejection_notice n JOIN vv_app.source_span s ON (s.tenant_id,s.project_id,s.id)=(n.tenant_id,n.project_id,n.source_span_id) WHERE n.tenant_id=t AND n.project_id=p
$$;
REVOKE ALL ON FUNCTION vv_api.import_rejection_notice(uuid,uuid,uuid,uuid,uuid,integer,integer,integer,text,text),vv_private.rejection_notices(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.import_rejection_notice(uuid,uuid,uuid,uuid,uuid,integer,integer,integer,text,text) TO verivaro_runtime;
CREATE OR REPLACE FUNCTION vv_api.workspace(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_api AS $$
DECLARE g jsonb;ms jsonb;cs jsonb;src jsonb;ts text;
BEGIN
 g:=vv_api.graph(t,p);
 SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') INTO ts;
 WITH latest AS(SELECT DISTINCT ON (id) * FROM vv_app.prooflock_revision WHERE tenant_id=t AND project_id=p ORDER BY id,revision DESC)
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',l.id,'revision',l.revision,'requirementId',r.requirement_id,'requirementRevision',r.revision,'requirementVersionId',r.id,'title',l.title,'milestone',to_char(l.milestone_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'confirmed',l.confirmed,'leadMinutes',l.lead_minutes,'irreversibility',l.risk) ORDER BY l.id),'[]'::jsonb) INTO ms
 FROM latest l JOIN vv_app.requirement_version r ON (r.tenant_id,r.project_id,r.id)=(l.tenant_id,l.project_id,l.requirement_version_id);
 WITH latest AS(SELECT DISTINCT ON (id) * FROM vv_app.rejection_event WHERE tenant_id=t AND project_id=p ORDER BY id,revision DESC)
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',l.id,'revision',l.revision,'requirementId',r.requirement_id,'requirementRevision',r.revision,'requirementVersionId',r.id,'state',l.state,'note',l.note) ORDER BY l.id),'[]'::jsonb) INTO cs
 FROM latest l JOIN vv_app.requirement_version r ON (r.tenant_id,r.project_id,r.id)=(l.tenant_id,l.project_id,l.requirement_version_id);
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',d.id,'originalSha256',d.content_sha256,'textSha256',o.text_sha256,'pages',coalesce((SELECT jsonb_agg(jsonb_build_object('page',v.page,'start',v.start_cp,'length',v.length_cp,'sha256',v.text_sha256,'method',v.method) ORDER BY v.page) FROM vv_app.version_page v WHERE v.tenant_id=t AND v.project_id=p AND v.version_id=d.id),'[]'::jsonb)) ORDER BY d.id),'[]'::jsonb) INTO src
 FROM vv_app.document_version d JOIN vv_app.version_origin o ON (o.tenant_id,o.project_id,o.version_id)=(d.tenant_id,d.project_id,d.id) WHERE d.tenant_id=t AND d.project_id=p;
 RETURN jsonb_build_object('asOf',ts,'graph',g,'milestones',ms,'cases',cs,'lineage',src,'contractRelations',vv_private.contract_relations(t,p),'rejectionNotices',vv_private.rejection_notices(t,p));
END $$;
RESET ROLE;
COMMIT;
