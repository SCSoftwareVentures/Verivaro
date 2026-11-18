BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.prooflock_revision(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),
 requirement_version_id uuid NOT NULL,title text NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 200),
 milestone_at timestamptz,confirmed boolean NOT NULL,lead_minutes integer NOT NULL CHECK(lead_minutes BETWEEN 0 AND 525600),
 risk text NOT NULL CHECK(risk IN ('reversible','costly','irreversible')),reviewer_id uuid NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,requirement_version_id) REFERENCES vv_app.requirement_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,reviewer_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK(confirmed=(milestone_at IS NOT NULL)),
 CHECK(milestone_at IS NULL OR (milestone_at>=TIMESTAMPTZ '2000-01-01 00:00:00+00' AND milestone_at<TIMESTAMPTZ '2101-01-01 00:00:00+00'))
);
CREATE TABLE vv_app.rejection_event(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),
 requirement_version_id uuid NOT NULL,state text NOT NULL CHECK(state IN ('open','resolution-recorded')),
 note text NOT NULL CHECK(length(trim(note)) BETWEEN 1 AND 1000),reviewer_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,requirement_version_id) REFERENCES vv_app.requirement_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,reviewer_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_app.handover_draft(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,generation bigint NOT NULL CHECK(generation>=0),
 scope_confirmed boolean NOT NULL,payload text NOT NULL CHECK(octet_length(payload)<=25165824),
 sha256 text NOT NULL CHECK(sha256=encode(vv_crypto.digest(convert_to(payload,'UTF8'),'sha256'),'hex')),
 created_by uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),FOREIGN KEY(tenant_id,project_id) REFERENCES vv_app.project(tenant_id,id),
 FOREIGN KEY(tenant_id,project_id,created_by) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
DO $$ DECLARE rel regclass;
BEGIN FOREACH rel IN ARRAY ARRAY['vv_app.prooflock_revision'::regclass,'vv_app.rejection_event'::regclass,'vv_app.handover_draft'::regclass] LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',rel);EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',rel);
 EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING(true) WITH CHECK(true)',rel);
 END LOOP;END $$;
CREATE FUNCTION vv_private.current_requirement(t uuid,p uuid,v uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,vv_app AS $$
 SELECT EXISTS(SELECT 1 FROM vv_app.requirement_version r WHERE r.tenant_id=t AND r.project_id=p AND r.id=v AND r.approved_by IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM vv_app.requirement_version n WHERE n.tenant_id=t AND n.project_id=p AND n.requirement_id=r.requirement_id AND n.revision>r.revision))
$$;
CREATE FUNCTION vv_api.save_prooflock(t uuid,p uuid,m uuid,prior integer,req uuid,n text,instant timestamptz,confirmed_date boolean,lead integer,risk_level text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.prooflock_revision%ROWTYPE;
BEGIN a:=vv_private.graph_lock(t,p);
 IF m IS NULL OR prior IS NULL OR prior<0 OR prior>=2147483647 OR n IS NULL OR length(trim(n)) NOT BETWEEN 1 AND 200 OR confirmed_date IS NULL OR confirmed_date<>(instant IS NOT NULL) OR lead IS NULL OR lead NOT BETWEEN 0 AND 525600 OR risk_level IS NULL OR risk_level NOT IN ('reversible','costly','irreversible') THEN RAISE EXCEPTION 'invalid milestone' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.prooflock_revision WHERE tenant_id=t AND project_id=p AND id=m ORDER BY revision DESC LIMIT 1;
 IF old.revision=prior+1 AND (old.requirement_version_id,old.title,old.milestone_at,old.confirmed,old.lead_minutes,old.risk,old.reviewer_id) IS NOT DISTINCT FROM (req,n,instant,confirmed_date,lead,risk_level,a) THEN RETURN old.revision;END IF;
 IF coalesce(old.revision,0)<>prior THEN RAISE EXCEPTION 'stale milestone' USING ERRCODE='23505';END IF;
 IF NOT vv_private.current_requirement(t,p,req) THEN RAISE EXCEPTION 'current requirement unavailable' USING ERRCODE='42501';END IF;
 IF old.id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM vv_app.requirement_version x JOIN vv_app.requirement_version y ON (y.tenant_id,y.project_id,y.requirement_id)=(x.tenant_id,x.project_id,x.requirement_id) WHERE x.tenant_id=t AND x.project_id=p AND x.id=old.requirement_version_id AND y.id=req) THEN RAISE EXCEPTION 'milestone requirement cannot change' USING ERRCODE='22023';END IF;
 IF (SELECT count(*) FROM vv_app.prooflock_revision WHERE tenant_id=t AND project_id=p)>=2000 THEN RAISE EXCEPTION 'milestone limit' USING ERRCODE='54000';END IF;
 INSERT INTO vv_app.prooflock_revision(tenant_id,project_id,id,revision,requirement_version_id,title,milestone_at,confirmed,lead_minutes,risk,reviewer_id) VALUES(t,p,m,prior+1,req,n,instant,confirmed_date,lead,risk_level,a);
 PERFORM vv_private.bump_graph(t,p);RETURN prior+1;
END $$;
CREATE FUNCTION vv_api.save_rejection(t uuid,p uuid,c uuid,prior integer,req uuid,new_state text,details text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.rejection_event%ROWTYPE;
BEGIN a:=vv_private.graph_lock(t,p);
 IF c IS NULL OR prior IS NULL OR prior<0 OR prior>=2147483647 OR new_state IS NULL OR new_state NOT IN ('open','resolution-recorded') OR details IS NULL OR length(trim(details)) NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'invalid rejection event' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.rejection_event WHERE tenant_id=t AND project_id=p AND id=c ORDER BY revision DESC LIMIT 1;
 IF old.revision=prior+1 AND (old.requirement_version_id,old.state,old.note,old.reviewer_id) IS NOT DISTINCT FROM (req,new_state,details,a) THEN RETURN old.revision;END IF;
 IF coalesce(old.revision,0)<>prior THEN RAISE EXCEPTION 'stale case' USING ERRCODE='23505';END IF;
 IF prior=0 AND (new_state<>'open' OR NOT vv_private.current_requirement(t,p,req)) THEN RAISE EXCEPTION 'new case must reference current requirement' USING ERRCODE='22023';END IF;
 IF prior>0 AND (old.requirement_version_id<>req OR old.state=new_state) THEN RAISE EXCEPTION 'invalid case transition' USING ERRCODE='22023';END IF;
 IF (SELECT count(*) FROM vv_app.rejection_event WHERE tenant_id=t AND project_id=p)>=2000 THEN RAISE EXCEPTION 'case limit' USING ERRCODE='54000';END IF;
 INSERT INTO vv_app.rejection_event(tenant_id,project_id,id,revision,requirement_version_id,state,note,reviewer_id) VALUES(t,p,c,prior+1,req,new_state,details,a);
 PERFORM vv_private.bump_graph(t,p);RETURN prior+1;
END $$;
CREATE FUNCTION vv_api.workspace(t uuid,p uuid) RETURNS jsonb
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
 RETURN jsonb_build_object('asOf',ts,'graph',g,'milestones',ms,'cases',cs,'lineage',src);
END $$;
-- Author runtime cannot submit a fabricated snapshot payload or mark it final.
CREATE FUNCTION vv_api.create_handover(t uuid,p uuid,h uuid,expected_generation bigint) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_api,vv_crypto AS $$
DECLARE a uuid;w jsonb;body text;old vv_app.handover_draft%ROWTYPE;actual bigint;
BEGIN a:=vv_private.graph_lock(t,p);
 IF h IS NULL OR expected_generation IS NULL OR expected_generation<0 THEN RAISE EXCEPTION 'invalid draft' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.handover_draft WHERE tenant_id=t AND project_id=p AND id=h;
 IF FOUND THEN IF old.generation=expected_generation AND old.created_by=a THEN RETURN h;END IF;RAISE EXCEPTION 'draft conflict' USING ERRCODE='23505';END IF;
 w:=vv_api.workspace(t,p);actual:=(w->'graph'->>'generation')::bigint;
 IF actual<>expected_generation THEN RAISE EXCEPTION 'stale generation' USING ERRCODE='23505';END IF;
 IF (SELECT count(*) FROM vv_app.handover_draft WHERE tenant_id=t AND project_id=p)>=20 THEN RAISE EXCEPTION 'draft quota' USING ERRCODE='54000';END IF;
 body:=w::text;
 INSERT INTO vv_app.handover_draft(tenant_id,project_id,id,generation,scope_confirmed,payload,sha256,created_by)
 VALUES(t,p,h,actual,(w->'graph'->>'scopeConfirmed')::boolean,body,encode(vv_crypto.digest(convert_to(body,'UTF8'),'sha256'),'hex'),a);
 RETURN h;
END $$;
CREATE FUNCTION vv_api.read_handover(t uuid,p uuid,h uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;d vv_app.handover_draft%ROWTYPE;g bigint;confirmed boolean;
BEGIN a:=vv_private.graph_lock(t,p);
 SELECT * INTO d FROM vv_app.handover_draft WHERE tenant_id=t AND project_id=p AND id=h;
 IF NOT FOUND THEN RAISE EXCEPTION 'draft unavailable' USING ERRCODE='42501';END IF;
 SELECT generation,coalesce(generation=confirmed_generation,false) INTO g,confirmed FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;
 RETURN jsonb_build_object('id',h,'payload',d.payload,'sha256',d.sha256,'stale',d.generation<>coalesce(g,0) OR d.scope_confirmed<>coalesce(confirmed,false));
END $$;
REVOKE ALL ON FUNCTION vv_private.current_requirement(uuid,uuid,uuid),vv_api.save_prooflock(uuid,uuid,uuid,integer,uuid,text,timestamptz,boolean,integer,text),vv_api.save_rejection(uuid,uuid,uuid,integer,uuid,text,text),vv_api.workspace(uuid,uuid),vv_api.create_handover(uuid,uuid,uuid,bigint),vv_api.read_handover(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.save_prooflock(uuid,uuid,uuid,integer,uuid,text,timestamptz,boolean,integer,text),vv_api.save_rejection(uuid,uuid,uuid,integer,uuid,text,text),vv_api.workspace(uuid,uuid),vv_api.create_handover(uuid,uuid,uuid,bigint),vv_api.read_handover(uuid,uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
