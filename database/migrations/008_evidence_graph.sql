BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.version_origin(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,version_id uuid NOT NULL,intent_id uuid NOT NULL,
 text_sha256 text NOT NULL CHECK(text_sha256 ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,project_id,version_id),UNIQUE(tenant_id,project_id,intent_id),
 FOREIGN KEY(tenant_id,project_id,version_id) REFERENCES vv_app.document_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_private.extract_job(tenant_id,project_id,intent_id)
);
CREATE TABLE vv_app.version_page(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,version_id uuid NOT NULL,page integer NOT NULL CHECK(page BETWEEN 1 AND 20),
 start_cp integer NOT NULL CHECK(start_cp>=0),length_cp integer NOT NULL CHECK(length_cp>=0),
 text_sha256 text NOT NULL CHECK(text_sha256 ~ '^[0-9a-f]{64}$'),method text NOT NULL CHECK(method IN ('utf8-exact','pdf-text','ocr')),
 PRIMARY KEY(tenant_id,project_id,version_id,page),
 FOREIGN KEY(tenant_id,project_id,version_id) REFERENCES vv_app.version_origin(tenant_id,project_id,version_id)
);
CREATE TABLE vv_app.requirement_origin(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,version_id uuid NOT NULL,decision_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,project_id,version_id),UNIQUE(tenant_id,project_id,decision_id),
 FOREIGN KEY(tenant_id,project_id,version_id) REFERENCES vv_app.requirement_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,decision_id) REFERENCES vv_app.requirement_decision(tenant_id,project_id,id)
);
CREATE TABLE vv_app.evidence_retirement(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,evidence_id uuid NOT NULL,reviewer_id uuid NOT NULL,
 reason text NOT NULL CHECK(length(trim(reason)) BETWEEN 1 AND 500),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,evidence_id),
 FOREIGN KEY(tenant_id,project_id,evidence_id) REFERENCES vv_app.evidence_link(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,reviewer_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_app.scope_checkpoint(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
 confirmed_generation bigint,confirmed_by uuid,confirmed_at timestamptz,
 PRIMARY KEY(tenant_id,project_id),
 FOREIGN KEY(tenant_id,project_id) REFERENCES vv_app.project(tenant_id,id),
 FOREIGN KEY(tenant_id,project_id,confirmed_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK(confirmed_generation IS NULL OR confirmed_generation<=generation)
);
DO $$ DECLARE t regclass;BEGIN
 FOREACH t IN ARRAY ARRAY['vv_app.version_origin'::regclass,'vv_app.version_page'::regclass,'vv_app.requirement_origin'::regclass,'vv_app.evidence_retirement'::regclass,'vv_app.scope_checkpoint'::regclass] LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',t);EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',t);EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING(true) WITH CHECK(true)',t);END LOOP;
END $$;
-- Serialize graph changes per project. All graph reads take the same project lock.
CREATE FUNCTION vv_private.graph_lock(t uuid,p uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;
BEGIN a:=vv_private.review_actor(t,p);
 PERFORM 1 FROM vv_app.project WHERE tenant_id=t AND id=p FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'project unavailable' USING ERRCODE='42501';END IF;
 RETURN a;
END $$;
CREATE FUNCTION vv_private.bump_graph(t uuid,p uuid) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,vv_app AS $$
 INSERT INTO vv_app.scope_checkpoint(tenant_id,project_id,generation) VALUES(t,p,1)
 ON CONFLICT(tenant_id,project_id) DO UPDATE SET generation=vv_app.scope_checkpoint.generation+1
$$;
CREATE FUNCTION vv_api.promote_document(t uuid,p uuid,u uuid,v uuid,prior integer,source_digest text,text_digest text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_api,vv_crypto AS $$
DECLARE a uuid;d uuid;orig text;combined text;previous vv_app.document_version%ROWTYPE;old vv_app.version_origin%ROWTYPE;x record;offset_cp integer:=0;num integer;
BEGIN
 a:=vv_private.graph_lock(t,p);
 IF v IS NULL OR prior IS NULL OR prior<0 OR source_digest IS NULL OR text_digest IS NULL THEN RAISE EXCEPTION 'invalid revision' USING ERRCODE='22023';END IF;
 SELECT i.document_id,r.actual_sha256 INTO d,orig FROM vv_app.upload_intent i JOIN vv_app.quarantine_receipt r ON (r.tenant_id,r.project_id,r.intent_id)=(i.tenant_id,i.project_id,i.id) WHERE i.tenant_id=t AND i.project_id=p AND i.id=u;
 IF NOT FOUND THEN RAISE EXCEPTION 'source unavailable' USING ERRCODE='42501';END IF;
 SELECT string_agg(text_value,E'\n\f\n' ORDER BY page),count(*) INTO combined,num FROM vv_api.review_pages(t,p,u);
 IF num<1 OR orig IS DISTINCT FROM source_digest OR text_digest IS DISTINCT FROM encode(vv_crypto.digest(convert_to(combined,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'review digest mismatch' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.version_origin WHERE tenant_id=t AND project_id=p AND version_id=v;
 IF FOUND THEN
 IF old.intent_id=u AND old.text_sha256=text_digest AND EXISTS(SELECT 1 FROM vv_app.document_version WHERE tenant_id=t AND project_id=p AND id=v AND revision=prior+1 AND reviewed_by=a) THEN RETURN v;END IF;
 RAISE EXCEPTION 'revision conflict' USING ERRCODE='23505';END IF;
 SELECT * INTO previous FROM vv_app.document_version WHERE tenant_id=t AND project_id=p AND document_id=d ORDER BY revision DESC LIMIT 1;
 IF coalesce(previous.revision,0)<>prior OR prior=2147483647 THEN RAISE EXCEPTION 'stale revision' USING ERRCODE='23505';END IF;
 INSERT INTO vv_app.document_version(tenant_id,project_id,id,document_id,revision,content_sha256,extracted_text,scan_state,reviewed_by,supersedes_id,created_by)
 VALUES(t,p,v,d,prior+1,orig,combined,'clean',a,previous.id,a);
 INSERT INTO vv_app.version_origin VALUES(t,p,v,u,text_digest);
 FOR x IN SELECT * FROM vv_api.review_pages(t,p,u) ORDER BY page LOOP
 INSERT INTO vv_app.version_page VALUES(t,p,v,x.page,offset_cp,length(x.text_value),x.text_sha256,x.method);
 offset_cp:=offset_cp+length(x.text_value)+3;
 END LOOP;
 PERFORM vv_private.bump_graph(t,p);RETURN v;
END $$;
-- Exact page-relative codepoint span, verified against immutable canonical text and current revision.
CREATE FUNCTION vv_private.add_graph_span(t uuid,p uuid,s uuid,v uuid,pg integer,lo integer,hi integer,q text,digest text,a uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_app AS $$
DECLARE page_row vv_app.version_page%ROWTYPE;doc vv_app.document_version%ROWTYPE;
BEGIN
 SELECT * INTO doc FROM vv_app.document_version WHERE tenant_id=t AND project_id=p AND id=v;
 IF NOT FOUND OR doc.reviewed_by IS NULL OR doc.scan_state<>'clean' OR EXISTS(SELECT 1 FROM vv_app.document_version x WHERE x.tenant_id=t AND x.project_id=p AND x.document_id=doc.document_id AND x.revision>doc.revision) THEN RAISE EXCEPTION 'source is not current reviewed revision' USING ERRCODE='23505';END IF;
 SELECT * INTO page_row FROM vv_app.version_page WHERE tenant_id=t AND project_id=p AND version_id=v AND page=pg;
 IF NOT FOUND OR digest IS DISTINCT FROM page_row.text_sha256 OR lo IS NULL OR hi IS NULL OR lo<0 OR hi<=lo OR hi>page_row.length_cp OR hi-lo>2000 OR q IS NULL OR length(q)<>hi-lo OR substring(doc.extracted_text FROM page_row.start_cp+lo+1 FOR hi-lo) IS DISTINCT FROM q THEN RAISE EXCEPTION 'source mismatch' USING ERRCODE='22023';END IF;
 INSERT INTO vv_app.source_span(tenant_id,project_id,id,document_version_id,start_cp,end_cp,quote,created_by)
 VALUES(t,p,s,v,page_row.start_cp+lo,page_row.start_cp+hi,q,a);
 RETURN s;
END $$;
CREATE FUNCTION vv_api.promote_requirement(t uuid,p uuid,d uuid,r uuid,v uuid,prior integer,s uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;dec vv_app.requirement_decision%ROWTYPE;src uuid;previous vv_app.requirement_version%ROWTYPE;old vv_app.requirement_origin%ROWTYPE;
BEGIN
 a:=vv_private.graph_lock(t,p);
 IF prior IS NULL OR prior<0 OR prior=2147483647 OR r IS NULL OR v IS NULL OR s IS NULL THEN RAISE EXCEPTION 'invalid requirement revision' USING ERRCODE='22023';END IF;
 SELECT * INTO dec FROM vv_app.requirement_decision WHERE tenant_id=t AND project_id=p AND id=d AND decision='approved';
 IF NOT FOUND THEN RAISE EXCEPTION 'approved proposal unavailable' USING ERRCODE='42501';END IF;
 SELECT version_id INTO src FROM vv_app.version_origin WHERE tenant_id=t AND project_id=p AND intent_id=dec.intent_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'reviewed source required' USING ERRCODE='23505';END IF;
 SELECT * INTO old FROM vv_app.requirement_origin WHERE tenant_id=t AND project_id=p AND version_id=v;
 IF FOUND THEN
 IF old.decision_id=d AND EXISTS(SELECT 1 FROM vv_app.requirement_version WHERE tenant_id=t AND project_id=p AND id=v AND requirement_id=r AND revision=prior+1 AND source_span_id=s AND approved_by=a) THEN RETURN v;END IF;
 RAISE EXCEPTION 'requirement revision conflict' USING ERRCODE='23505';END IF;
 SELECT * INTO previous FROM vv_app.requirement_version WHERE tenant_id=t AND project_id=p AND requirement_id=r ORDER BY revision DESC LIMIT 1;
 IF coalesce(previous.revision,0)<>prior THEN RAISE EXCEPTION 'stale requirement' USING ERRCODE='23505';END IF;
 PERFORM vv_private.add_graph_span(t,p,s,src,dec.page,dec.start_cp,dec.end_cp,dec.quote,dec.text_sha256,a);
 IF prior=0 THEN INSERT INTO vv_app.requirement(tenant_id,project_id,id,created_by) VALUES(t,p,r,a);END IF;
 INSERT INTO vv_app.requirement_version(tenant_id,project_id,id,requirement_id,revision,source_span_id,mandatory,applicability,criterion_kind,expected,approved_by,supersedes_id,created_by)
 VALUES(t,p,v,r,prior+1,s,dec.mandatory,'applicable',dec.criterion_kind,dec.expected,a,previous.id,a);
 INSERT INTO vv_app.requirement_origin VALUES(t,p,v,d);PERFORM vv_private.bump_graph(t,p);RETURN v;
END $$;
CREATE FUNCTION vv_api.link_evidence(t uuid,p uuid,e uuid,r uuid,s uuid,v uuid,pg integer,lo integer,hi integer,q text,digest text,verdict text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;req vv_app.requirement_version%ROWTYPE;old vv_app.evidence_link%ROWTYPE;
BEGIN
 a:=vv_private.graph_lock(t,p);
 IF e IS NULL OR s IS NULL OR verdict IS NULL OR verdict NOT IN ('approved','rejected') OR q IS NULL OR length(trim(q)) NOT BETWEEN 1 AND 500 THEN RAISE EXCEPTION 'invalid evidence' USING ERRCODE='22023';END IF;
 SELECT * INTO req FROM vv_app.requirement_version WHERE tenant_id=t AND project_id=p AND id=r AND approved_by IS NOT NULL;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM vv_app.requirement_version x WHERE x.tenant_id=t AND x.project_id=p AND x.requirement_id=req.requirement_id AND x.revision>req.revision) THEN RAISE EXCEPTION 'requirement unavailable' USING ERRCODE='42501';END IF;
 -- A requirement document is not its own evidence, including older versions of the same logical document.
 IF EXISTS(SELECT 1 FROM vv_app.source_span sp JOIN vv_app.document_version contract ON (contract.tenant_id,contract.project_id,contract.id)=(sp.tenant_id,sp.project_id,sp.document_version_id)
 JOIN vv_app.document_version cert ON (cert.tenant_id,cert.project_id,cert.document_id)=(contract.tenant_id,contract.project_id,contract.document_id)
 WHERE sp.tenant_id=t AND sp.project_id=p AND sp.id=req.source_span_id AND cert.id=v) THEN RAISE EXCEPTION 'separate evidence required' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.evidence_link WHERE tenant_id=t AND project_id=p AND id=e;
 IF FOUND THEN
 IF old.requirement_version_id=r AND old.source_span_id=s AND old.asserted_value=q AND old.review_state=verdict AND old.reviewed_by=a AND EXISTS(
 SELECT 1 FROM vv_app.source_span sp JOIN vv_app.version_page vp ON (vp.tenant_id,vp.project_id,vp.version_id)=(sp.tenant_id,sp.project_id,sp.document_version_id)
 WHERE sp.tenant_id=t AND sp.project_id=p AND sp.id=s AND sp.document_version_id=v AND vp.page=pg AND vp.text_sha256=digest AND sp.start_cp=vp.start_cp+lo AND sp.end_cp=vp.start_cp+hi AND sp.quote=q) THEN RETURN e;END IF;
 RAISE EXCEPTION 'evidence conflict' USING ERRCODE='23505';END IF;
 PERFORM vv_private.add_graph_span(t,p,s,v,pg,lo,hi,q,digest,a);
 INSERT INTO vv_app.evidence_link(tenant_id,project_id,id,requirement_version_id,source_span_id,kind,asserted_value,review_state,reviewed_by,created_by)
 VALUES(t,p,e,r,s,req.criterion_kind,q,verdict,a,a);PERFORM vv_private.bump_graph(t,p);RETURN e;
END $$;
CREATE FUNCTION vv_api.retire_evidence(t uuid,p uuid,e uuid,why text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.evidence_retirement%ROWTYPE;
BEGIN a:=vv_private.graph_lock(t,p);
 IF why IS NULL OR length(trim(why)) NOT BETWEEN 1 AND 500 THEN RAISE EXCEPTION 'reason required' USING ERRCODE='22023';END IF;
 IF NOT EXISTS(SELECT 1 FROM vv_app.evidence_link l JOIN vv_app.source_span s ON (s.tenant_id,s.project_id,s.id)=(l.tenant_id,l.project_id,l.source_span_id)
 JOIN vv_app.document_version d ON (d.tenant_id,d.project_id,d.id)=(s.tenant_id,s.project_id,s.document_version_id)
 WHERE l.tenant_id=t AND l.project_id=p AND l.id=e AND EXISTS(SELECT 1 FROM vv_app.document_version n WHERE n.tenant_id=t AND n.project_id=p AND n.document_id=d.document_id AND n.revision>d.revision)) THEN RAISE EXCEPTION 'only superseded evidence can be retired' USING ERRCODE='42501';END IF;
 SELECT * INTO old FROM vv_app.evidence_retirement WHERE tenant_id=t AND project_id=p AND evidence_id=e;
 IF FOUND THEN IF old.reason=why AND old.reviewer_id=a THEN RETURN e;END IF;RAISE EXCEPTION 'retirement conflict' USING ERRCODE='23505';END IF;
 INSERT INTO vv_app.evidence_retirement(tenant_id,project_id,evidence_id,reviewer_id,reason) VALUES(t,p,e,a,why);
 PERFORM vv_private.bump_graph(t,p);RETURN e;
END $$;
CREATE FUNCTION vv_api.confirm_scope(t uuid,p uuid,g bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;actual bigint;BEGIN a:=vv_private.graph_lock(t,p);
 SELECT generation INTO actual FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;
 IF g IS NULL OR actual IS NULL OR actual<>g OR NOT EXISTS(SELECT 1 FROM vv_app.requirement_version WHERE tenant_id=t AND project_id=p) THEN RAISE EXCEPTION 'scope changed or empty' USING ERRCODE='23505';END IF;
 UPDATE vv_app.scope_checkpoint SET confirmed_generation=g,confirmed_by=a,confirmed_at=clock_timestamp() WHERE tenant_id=t AND project_id=p;
 RETURN g;
END $$;
-- Read one consistent, bounded graph. No raw runtime SELECT grants; project scope and reviewer enforced.
CREATE FUNCTION vv_api.graph(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;out jsonb;g bigint;cg bigint;
BEGIN a:=vv_private.graph_lock(t,p);
 IF (SELECT count(*) FROM vv_app.document_version WHERE tenant_id=t AND project_id=p)>200 OR
 (SELECT coalesce(sum(octet_length(extracted_text)),0) FROM vv_app.document_version WHERE tenant_id=t AND project_id=p)>16777216 OR
 (SELECT count(*) FROM vv_app.requirement_version WHERE tenant_id=t AND project_id=p)>1000 OR
 (SELECT count(*) FROM vv_app.evidence_link WHERE tenant_id=t AND project_id=p)>5000 THEN RAISE EXCEPTION 'graph exceeds demo limit' USING ERRCODE='54000';END IF;
 SELECT generation,confirmed_generation INTO g,cg FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;
 WITH req AS(SELECT DISTINCT ON (requirement_id) * FROM vv_app.requirement_version WHERE tenant_id=t AND project_id=p ORDER BY requirement_id,revision DESC)
 SELECT jsonb_build_object('generation',coalesce(g,0)::text,'scopeConfirmed',coalesce(g=cg,false),
 'sources',coalesce((SELECT jsonb_agg(jsonb_build_object('id',d.id,'documentId',d.document_id,'revision',d.revision,'text',coalesce(d.extracted_text,''),'scan',CASE WHEN d.scan_state='quarantined' THEN 'pending' ELSE d.scan_state END,'reviewed',d.reviewed_by IS NOT NULL,'current',NOT EXISTS(SELECT 1 FROM vv_app.document_version n WHERE n.tenant_id=t AND n.project_id=p AND n.document_id=d.document_id AND n.revision>d.revision))) FROM vv_app.document_version d WHERE d.tenant_id=t AND d.project_id=p),'[]'::jsonb),
 'requirements',coalesce((SELECT jsonb_agg(jsonb_build_object('id',r.requirement_id,'revision',r.revision,'approved',r.approved_by IS NOT NULL,'applicability',r.applicability,'mandatory',r.mandatory,'span',jsonb_build_object('sourceId',s.document_version_id,'start',s.start_cp,'end',s.end_cp,'quote',s.quote),'criterion',jsonb_build_object('kind',r.criterion_kind,'expected',r.expected))) FROM req r JOIN vv_app.source_span s ON (s.tenant_id,s.project_id,s.id)=(r.tenant_id,r.project_id,r.source_span_id)),'[]'::jsonb),
 'evidence',coalesce((SELECT jsonb_agg(jsonb_build_object('id',e.id,'requirementId',r.requirement_id,'requirementRevision',r.revision,'span',jsonb_build_object('sourceId',s.document_version_id,'start',s.start_cp,'end',s.end_cp,'quote',s.quote),'kind',e.kind,'value',e.asserted_value,'review',e.review_state)) FROM vv_app.evidence_link e JOIN vv_app.requirement_version r ON (r.tenant_id,r.project_id,r.id)=(e.tenant_id,e.project_id,e.requirement_version_id) JOIN vv_app.source_span s ON (s.tenant_id,s.project_id,s.id)=(e.tenant_id,e.project_id,e.source_span_id) WHERE e.tenant_id=t AND e.project_id=p AND NOT EXISTS(SELECT 1 FROM vv_app.evidence_retirement x WHERE x.tenant_id=t AND x.project_id=p AND x.evidence_id=e.id)),'[]'::jsonb)) INTO out;
 RETURN out;
END $$;
REVOKE ALL ON FUNCTION vv_private.graph_lock(uuid,uuid),vv_private.bump_graph(uuid,uuid),vv_private.add_graph_span(uuid,uuid,uuid,uuid,integer,integer,integer,text,text,uuid),vv_api.promote_document(uuid,uuid,uuid,uuid,integer,text,text),vv_api.promote_requirement(uuid,uuid,uuid,uuid,uuid,integer,uuid),vv_api.link_evidence(uuid,uuid,uuid,uuid,uuid,uuid,integer,integer,integer,text,text,text),vv_api.retire_evidence(uuid,uuid,uuid,text),vv_api.confirm_scope(uuid,uuid,bigint),vv_api.graph(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.promote_document(uuid,uuid,uuid,uuid,integer,text,text),vv_api.promote_requirement(uuid,uuid,uuid,uuid,uuid,integer,uuid),vv_api.link_evidence(uuid,uuid,uuid,uuid,uuid,uuid,integer,integer,integer,text,text,text),vv_api.retire_evidence(uuid,uuid,uuid,text),vv_api.confirm_scope(uuid,uuid,bigint),vv_api.graph(uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
