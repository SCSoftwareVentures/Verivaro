BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.contract_relation(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),
 amendment_version_id uuid NOT NULL,base_version_id uuid NOT NULL,source_span_id uuid NOT NULL,
 relation text NOT NULL CHECK(relation IN ('amends','supersedes','qualifies','conflicts')),
 state text NOT NULL CHECK(state IN ('unresolved','reviewed','withdrawn')),
 note text NOT NULL CHECK(length(trim(note)) BETWEEN 1 AND 1000),reviewer_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,amendment_version_id) REFERENCES vv_app.document_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,base_version_id) REFERENCES vv_app.document_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,source_span_id) REFERENCES vv_app.source_span(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,reviewer_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK(amendment_version_id<>base_version_id)
);
ALTER TABLE vv_app.contract_relation ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_app.contract_relation FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_app.contract_relation TO verivaro_owner USING(true) WITH CHECK(true);
CREATE FUNCTION vv_private.current_document(t uuid,p uuid,v uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,vv_app AS $$
 SELECT EXISTS(SELECT 1 FROM vv_app.document_version d WHERE d.tenant_id=t AND d.project_id=p AND d.id=v AND d.reviewed_by IS NOT NULL AND d.scan_state='clean'
 AND NOT EXISTS(SELECT 1 FROM vv_app.document_version n WHERE n.tenant_id=t AND n.project_id=p AND n.document_id=d.document_id AND n.revision>d.revision))
$$;
CREATE FUNCTION vv_api.save_relation(t uuid,p uuid,i uuid,prior integer,amend uuid,base uuid,s uuid,pg integer,lo integer,hi integer,q text,digest text,rel text,decision text,details text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.contract_relation%ROWTYPE;ad uuid;bd uuid;cycle boolean;
BEGIN a:=vv_private.graph_lock(t,p);
 IF i IS NULL OR s IS NULL OR prior IS NULL OR prior<0 OR prior>=2147483647 OR amend IS NULL OR base IS NULL OR amend=base OR rel IS NULL OR rel NOT IN ('amends','supersedes','qualifies','conflicts') OR decision IS NULL OR decision NOT IN ('unresolved','reviewed','withdrawn') OR (prior=0 AND decision='withdrawn') OR details IS NULL OR length(trim(details)) NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'invalid relation' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.contract_relation WHERE tenant_id=t AND project_id=p AND id=i ORDER BY revision DESC LIMIT 1;
 IF old.revision=prior+1 AND (old.amendment_version_id,old.base_version_id,old.source_span_id,old.relation,old.state,old.note,old.reviewer_id) IS NOT DISTINCT FROM (amend,base,s,rel,decision,details,a)
 AND EXISTS(SELECT 1 FROM vv_app.source_span ss JOIN vv_app.version_page vp ON (vp.tenant_id,vp.project_id,vp.version_id)=(ss.tenant_id,ss.project_id,ss.document_version_id)
 WHERE ss.tenant_id=t AND ss.project_id=p AND ss.id=s AND ss.document_version_id=amend AND vp.page=pg AND vp.text_sha256=digest AND ss.start_cp=vp.start_cp+lo AND ss.end_cp=vp.start_cp+hi AND ss.quote=q) THEN RETURN old.revision;END IF;
 IF coalesce(old.revision,0)<>prior THEN RAISE EXCEPTION 'stale relation' USING ERRCODE='23505';END IF;
 IF NOT vv_private.current_document(t,p,amend) OR NOT vv_private.current_document(t,p,base) THEN RAISE EXCEPTION 'reviewed source unavailable' USING ERRCODE='42501';END IF;
 SELECT document_id INTO ad FROM vv_app.document_version WHERE tenant_id=t AND project_id=p AND id=amend;
 SELECT document_id INTO bd FROM vv_app.document_version WHERE tenant_id=t AND project_id=p AND id=base;
 IF ad=bd THEN RAISE EXCEPTION 'separate documents required' USING ERRCODE='22023';END IF;
 IF prior>0 AND NOT EXISTS(SELECT 1 FROM vv_app.document_version x JOIN vv_app.document_version y ON (y.tenant_id,y.project_id)=(x.tenant_id,x.project_id)
 WHERE x.tenant_id=t AND x.project_id=p AND x.id=old.amendment_version_id AND y.id=old.base_version_id AND x.document_id=ad AND y.document_id=bd) THEN RAISE EXCEPTION 'cannot change relation documents' USING ERRCODE='22023';END IF;
 -- A directed precedence cycle is never automatically reconciled. Ignore only explicitly withdrawn edges.
 IF decision<>'withdrawn' AND rel<>'conflicts' THEN
 WITH RECURSIVE latest AS(SELECT DISTINCT ON (x.id) x.* FROM vv_app.contract_relation x WHERE x.tenant_id=t AND x.project_id=p AND x.id<>i ORDER BY x.id,x.revision DESC),
 edges AS(SELECT a0.document_id src,b0.document_id dst FROM latest l JOIN vv_app.document_version a0 ON (a0.tenant_id,a0.project_id,a0.id)=(l.tenant_id,l.project_id,l.amendment_version_id)
 JOIN vv_app.document_version b0 ON (b0.tenant_id,b0.project_id,b0.id)=(l.tenant_id,l.project_id,l.base_version_id)
 WHERE l.state<>'withdrawn' AND l.relation<>'conflicts'),
 reach(node) AS(SELECT bd UNION SELECT e.dst FROM reach r JOIN edges e ON e.src=r.node)
 SELECT EXISTS(SELECT 1 FROM reach WHERE node=ad) INTO cycle;
 IF cycle THEN RAISE EXCEPTION 'precedence cycle' USING ERRCODE='22023';END IF;
 END IF;
 IF (SELECT count(*) FROM vv_app.contract_relation WHERE tenant_id=t AND project_id=p)>=2000 THEN RAISE EXCEPTION 'relation quota' USING ERRCODE='54000';END IF;
 PERFORM vv_private.add_graph_span(t,p,s,amend,pg,lo,hi,q,digest,a);
 INSERT INTO vv_app.contract_relation(tenant_id,project_id,id,revision,amendment_version_id,base_version_id,source_span_id,relation,state,note,reviewer_id)
 VALUES(t,p,i,prior+1,amend,base,s,rel,decision,details,a);
 PERFORM vv_private.bump_graph(t,p);RETURN prior+1;
END $$;
CREATE FUNCTION vv_private.contract_relations(t uuid,p uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
 WITH latest AS(SELECT DISTINCT ON (id) * FROM vv_app.contract_relation WHERE tenant_id=t AND project_id=p ORDER BY id,revision DESC)
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',l.id,'revision',l.revision,'amendmentVersionId',l.amendment_version_id,'baseVersionId',l.base_version_id,'relation',l.relation,'state',l.state,'note',l.note,'quote',s.quote,'sourceStart',s.start_cp,'sourceEnd',s.end_cp,'current',vv_private.current_document(t,p,l.amendment_version_id) AND vv_private.current_document(t,p,l.base_version_id)) ORDER BY l.id),'[]'::jsonb)
 FROM latest l JOIN vv_app.source_span s ON (s.tenant_id,s.project_id,s.id)=(l.tenant_id,l.project_id,l.source_span_id)
$$;
REVOKE ALL ON FUNCTION vv_private.current_document(uuid,uuid,uuid),vv_private.contract_relations(uuid,uuid),vv_api.save_relation(uuid,uuid,uuid,integer,uuid,uuid,uuid,integer,integer,integer,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.save_relation(uuid,uuid,uuid,integer,uuid,uuid,uuid,integer,integer,integer,text,text,text,text,text) TO verivaro_runtime;
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
 RETURN jsonb_build_object('asOf',ts,'graph',g,'milestones',ms,'cases',cs,'lineage',src,'contractRelations',vv_private.contract_relations(t,p));
END $$;
RESET ROLE;
COMMIT;
