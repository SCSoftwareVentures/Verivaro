BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.correction_plan(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,notice_id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),
 case_revision integer NOT NULL CHECK(case_revision>0),assignee uuid NOT NULL,document_version_id uuid NOT NULL,
 filename text NOT NULL CHECK(length(filename) BETWEEN 1 AND 120),cover_note text NOT NULL CHECK(length(trim(cover_note)) BETWEEN 1 AND 1500),
 state text NOT NULL CHECK(state IN ('draft','approved')),reviewer_id uuid NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,notice_id,revision),
 FOREIGN KEY(tenant_id,project_id,notice_id) REFERENCES vv_app.rejection_notice(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,notice_id,case_revision) REFERENCES vv_app.rejection_event(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,assignee) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 FOREIGN KEY(tenant_id,project_id,reviewer_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 FOREIGN KEY(tenant_id,project_id,document_version_id) REFERENCES vv_app.document_version(tenant_id,project_id,id)
);
ALTER TABLE vv_app.correction_plan ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_app.correction_plan FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_app.correction_plan TO verivaro_owner USING(true) WITH CHECK(true);
CREATE FUNCTION vv_private.correction_assignee(t uuid,p uuid,a uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
 SELECT EXISTS(SELECT 1 FROM vv_private.project_member pm JOIN vv_private.membership m ON (m.tenant_id,m.actor_id)=(pm.tenant_id,pm.actor_id) WHERE pm.tenant_id=t AND pm.project_id=p AND pm.actor_id=a AND pm.active AND m.active AND pm.role IN ('owner','reviewer'))
$$;
CREATE FUNCTION vv_api.save_correction_plan(t uuid,p uuid,i uuid,prior integer,case_rev integer,assigned uuid,target uuid,filename_in text,cover text,decision text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.correction_plan%ROWTYPE;event vv_app.rejection_event%ROWTYPE;media text;ext text;
BEGIN
 a:=vv_private.graph_lock(t,p);
 IF i IS NULL OR prior IS NULL OR prior<0 OR prior>=2147483647 OR case_rev IS NULL OR case_rev<1 OR assigned IS NULL OR target IS NULL OR decision IS NULL OR decision NOT IN ('draft','approved') OR cover IS NULL OR length(trim(cover)) NOT BETWEEN 1 AND 1500 OR filename_in IS NULL OR length(filename_in)>120 OR filename_in !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,99}[.](pdf|png|jpg|txt)$' THEN RAISE EXCEPTION 'invalid correction plan' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.correction_plan WHERE tenant_id=t AND project_id=p AND notice_id=i ORDER BY revision DESC LIMIT 1;
 IF old.revision=prior+1 AND (old.case_revision,old.assignee,old.document_version_id,old.filename,old.cover_note,old.state,old.reviewer_id) IS NOT DISTINCT FROM (case_rev,assigned,target,filename_in,cover,decision,a) THEN RETURN old.revision;END IF;
 IF coalesce(old.revision,0)<>prior THEN RAISE EXCEPTION 'stale correction plan' USING ERRCODE='23505';END IF;
 IF NOT EXISTS(SELECT 1 FROM vv_app.rejection_notice WHERE tenant_id=t AND project_id=p AND id=i) THEN RAISE EXCEPTION 'notice unavailable' USING ERRCODE='42501';END IF;
 SELECT * INTO event FROM vv_app.rejection_event WHERE tenant_id=t AND project_id=p AND id=i ORDER BY revision DESC LIMIT 1;
 IF NOT FOUND OR event.revision<>case_rev OR event.state<>'open' OR NOT vv_private.current_requirement(t,p,event.requirement_version_id) THEN RAISE EXCEPTION 'current open case required' USING ERRCODE='23505';END IF;
 IF NOT vv_private.correction_assignee(t,p,assigned) OR NOT vv_private.current_document(t,p,target) THEN RAISE EXCEPTION 'assignment or source unavailable' USING ERRCODE='42501';END IF;
 SELECT u.media_type INTO media FROM vv_app.version_origin vo JOIN vv_app.upload_intent u ON (u.tenant_id,u.project_id,u.id)=(vo.tenant_id,vo.project_id,vo.intent_id) WHERE vo.tenant_id=t AND vo.project_id=p AND vo.version_id=target;
 ext:=CASE media WHEN 'application/pdf' THEN 'pdf' WHEN 'image/png' THEN 'png' WHEN 'image/jpeg' THEN 'jpg' WHEN 'text/plain' THEN 'txt' END;
 IF ext IS NULL OR right(filename_in,length(ext)+1)<>'.'||ext OR split_part(upper(filename_in),'.',1) ~ '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$' THEN RAISE EXCEPTION 'unsafe or mismatched filename' USING ERRCODE='22023';END IF;
 IF decision='approved' AND (prior=0 OR old.state<>'draft' OR (old.case_revision,old.assignee,old.document_version_id,old.filename,old.cover_note) IS DISTINCT FROM (case_rev,assigned,target,filename_in,cover)) THEN RAISE EXCEPTION 'approve exact existing draft only' USING ERRCODE='22023';END IF;
 IF (SELECT count(*) FROM vv_app.correction_plan WHERE tenant_id=t AND project_id=p)>=2000 THEN RAISE EXCEPTION 'correction plan quota' USING ERRCODE='54000';END IF;
 INSERT INTO vv_app.correction_plan(tenant_id,project_id,notice_id,revision,case_revision,assignee,document_version_id,filename,cover_note,state,reviewer_id) VALUES(t,p,i,prior+1,case_rev,assigned,target,filename_in,cover,decision,a);
 PERFORM vv_private.bump_graph(t,p);RETURN prior+1;
END $$;
CREATE FUNCTION vv_api.correction_queue(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;plans jsonb;roster jsonb;
BEGIN
 a:=vv_private.graph_lock(t,p);
 SELECT coalesce(jsonb_agg(pm.actor_id ORDER BY pm.actor_id),'[]'::jsonb) INTO roster FROM vv_private.project_member pm WHERE pm.tenant_id=t AND pm.project_id=p AND vv_private.correction_assignee(t,p,pm.actor_id);
 WITH latest AS(SELECT DISTINCT ON(notice_id) * FROM vv_app.correction_plan WHERE tenant_id=t AND project_id=p ORDER BY notice_id,revision DESC)
 SELECT coalesce(jsonb_agg(jsonb_build_object('noticeId',l.notice_id,'revision',l.revision,'caseRevision',l.case_revision,'assignee',l.assignee,'documentVersionId',l.document_version_id,'filename',l.filename,'coverNote',l.cover_note,'state',l.state,'originalSha256',d.content_sha256,'current',vv_private.current_document(t,p,l.document_version_id) AND vv_private.correction_assignee(t,p,l.assignee) AND EXISTS(SELECT 1 FROM vv_app.rejection_event e WHERE e.tenant_id=t AND e.project_id=p AND e.id=l.notice_id AND e.revision=l.case_revision AND e.state='open' AND vv_private.current_requirement(t,p,e.requirement_version_id) AND NOT EXISTS(SELECT 1 FROM vv_app.rejection_event newer WHERE newer.tenant_id=t AND newer.project_id=p AND newer.id=e.id AND newer.revision>e.revision)),'assignedToMe',l.assignee=a) ORDER BY l.notice_id),'[]'::jsonb) INTO plans
 FROM latest l JOIN vv_app.document_version d ON (d.tenant_id,d.project_id,d.id)=(l.tenant_id,l.project_id,l.document_version_id);
 RETURN jsonb_build_object('reviewers',roster,'plans',plans);
END $$;
REVOKE ALL ON FUNCTION vv_private.correction_assignee(uuid,uuid,uuid),vv_api.save_correction_plan(uuid,uuid,uuid,integer,integer,uuid,uuid,text,text,text),vv_api.correction_queue(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.save_correction_plan(uuid,uuid,uuid,integer,integer,uuid,uuid,text,text,text),vv_api.correction_queue(uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
