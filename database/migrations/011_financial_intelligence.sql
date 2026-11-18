BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.finance_revision(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),
 category text NOT NULL CHECK(category IN ('milestone','retention')),
 title text NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 200),
 amount text NOT NULL CHECK(amount~'^(0|[1-9][0-9]{0,11})\.[0-9]{2}$'),
 currency text NOT NULL CHECK(currency='AUD'),tax_basis text NOT NULL CHECK(tax_basis IN ('inclusive','exclusive')),
 source_span_id uuid NOT NULL,reviewer_id uuid NOT NULL,
 release_on date,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,source_span_id) REFERENCES vv_app.source_span(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,reviewer_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK(release_on IS NULL OR (category='retention' AND release_on BETWEEN DATE '2000-01-01' AND DATE '2100-12-31'))
);
CREATE TABLE vv_app.finance_condition(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,finance_id uuid NOT NULL,finance_revision integer NOT NULL,requirement_version_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,project_id,finance_id,finance_revision,requirement_version_id),
 FOREIGN KEY(tenant_id,project_id,finance_id,finance_revision) REFERENCES vv_app.finance_revision(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,requirement_version_id) REFERENCES vv_app.requirement_version(tenant_id,project_id,id)
);
CREATE TABLE vv_app.dispute_event(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,
 finance_id uuid NOT NULL,finance_revision integer NOT NULL,
 event_type text NOT NULL CHECK(event_type IN ('submission-asserted','delivery-asserted','receipt-asserted','acceptance-asserted','rejection-asserted','disputed','correction','payment-asserted','note')),
 occurred_at timestamptz, note text NOT NULL CHECK(length(trim(note)) BETWEEN 1 AND 2000),
 document_version_id uuid,handover_id uuid,actor_id uuid NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,finance_id,finance_revision) REFERENCES vv_app.finance_revision(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,document_version_id) REFERENCES vv_app.document_version(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,handover_id) REFERENCES vv_app.handover_draft(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,actor_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK(occurred_at IS NULL OR occurred_at>=TIMESTAMPTZ '2000-01-01 00:00:00+00')
);
CREATE INDEX dispute_finance ON vv_app.dispute_event(tenant_id,project_id,finance_id,recorded_at,id);
DO $$ DECLARE rel regclass;
BEGIN FOREACH rel IN ARRAY ARRAY['vv_app.finance_revision'::regclass,'vv_app.finance_condition'::regclass,'vv_app.dispute_event'::regclass] LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',rel);EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',rel);
 EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING(true) WITH CHECK(true)',rel);
 END LOOP;END $$;
-- Reviewed AUD literal must match the exact canonical page, not a number supplied by a client alone.
-- All writes share graph_lock, including finance origin deduplication and revision checks.
CREATE FUNCTION vv_api.save_finance(t uuid,p uuid,f uuid,prior integer,cat text,n text,amt text,basis text,s uuid,v uuid,pg integer,lo integer,hi integer,q text,digest text,release_date date,conditions uuid[]) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.finance_revision%ROWTYPE;ids uuid[];before_ids uuid[];page_row vv_app.version_page%ROWTYPE;doc vv_app.document_version%ROWTYPE;
BEGIN
 a:=vv_private.graph_lock(t,p);
 IF f IS NULL OR s IS NULL OR v IS NULL OR prior IS NULL OR prior<0 OR prior>=2147483647 OR cat IS NULL OR cat NOT IN ('milestone','retention') OR n IS NULL OR length(trim(n)) NOT BETWEEN 1 AND 200 OR amt IS NULL OR amt!~'^(0|[1-9][0-9]{0,11})\.[0-9]{2}$' OR basis IS NULL OR basis NOT IN ('inclusive','exclusive') OR q IS DISTINCT FROM ('AUD '||amt) OR conditions IS NULL OR cardinality(conditions)>100 OR array_position(conditions,NULL) IS NOT NULL OR (release_date IS NOT NULL AND (cat<>'retention' OR release_date NOT BETWEEN DATE '2000-01-01' AND DATE '2100-12-31')) THEN RAISE EXCEPTION 'invalid financial revision' USING ERRCODE='22023';END IF;
 SELECT coalesce(array_agg(z ORDER BY z),ARRAY[]::uuid[]) INTO ids FROM (SELECT DISTINCT unnest(conditions) z) x;
 IF cardinality(ids)<>cardinality(conditions) THEN RAISE EXCEPTION 'duplicate condition' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.finance_revision WHERE tenant_id=t AND project_id=p AND id=f ORDER BY revision DESC LIMIT 1;
 IF old.revision=prior+1 THEN
  SELECT coalesce(array_agg(requirement_version_id ORDER BY requirement_version_id),ARRAY[]::uuid[]) INTO before_ids FROM vv_app.finance_condition WHERE tenant_id=t AND project_id=p AND finance_id=f AND finance_revision=old.revision;
  IF (old.category,old.title,old.amount,old.tax_basis,old.source_span_id,old.release_on,old.reviewer_id,before_ids) IS NOT DISTINCT FROM (cat,n,amt,basis,s,release_date,a,ids)
  AND EXISTS(SELECT 1 FROM vv_app.source_span sp JOIN vv_app.version_page vp ON (vp.tenant_id,vp.project_id,vp.version_id)=(sp.tenant_id,sp.project_id,sp.document_version_id)
   WHERE sp.tenant_id=t AND sp.project_id=p AND sp.id=s AND sp.document_version_id=v AND vp.page=pg AND vp.text_sha256=digest AND sp.start_cp=vp.start_cp+lo AND sp.end_cp=vp.start_cp+hi AND sp.quote=q) THEN RETURN old.revision;END IF;
 END IF;
 IF coalesce(old.revision,0)<>prior OR (old.id IS NOT NULL AND old.category<>cat) THEN RAISE EXCEPTION 'financial revision conflict' USING ERRCODE='23505';END IF;
 IF EXISTS(SELECT 1 FROM unnest(ids) x WHERE NOT vv_private.current_requirement(t,p,x)) THEN RAISE EXCEPTION 'condition unavailable' USING ERRCODE='42501';END IF;
 SELECT * INTO doc FROM vv_app.document_version WHERE tenant_id=t AND project_id=p AND id=v;
 SELECT * INTO page_row FROM vv_app.version_page WHERE tenant_id=t AND project_id=p AND version_id=v AND page=pg;
 IF doc.id IS NULL OR page_row.page IS NULL OR lo IS NULL OR hi IS NULL OR lo<0 OR hi<=lo OR hi>page_row.length_cp OR hi-lo<>length(q) THEN RAISE EXCEPTION 'invalid amount span' USING ERRCODE='22023';END IF;
 -- Refuse cropped decimal/currency strings and reuse of the same source occurrence even under another logical ID.
 IF (lo>0 AND substring(doc.extracted_text FROM page_row.start_cp+lo FOR 1)~'[A-Za-z0-9.,]') OR (hi<page_row.length_cp AND substring(doc.extracted_text FROM page_row.start_cp+hi+1 FOR 1)~'[A-Za-z0-9.,]') THEN RAISE EXCEPTION 'partial amount' USING ERRCODE='22023';END IF;
 IF EXISTS(SELECT 1 FROM vv_app.finance_revision m JOIN vv_app.source_span sp ON (sp.tenant_id,sp.project_id,sp.id)=(m.tenant_id,m.project_id,m.source_span_id)
 JOIN vv_app.document_version d ON (d.tenant_id,d.project_id,d.id)=(sp.tenant_id,sp.project_id,sp.document_version_id)
 WHERE m.tenant_id=t AND m.project_id=p AND m.id<>f AND d.content_sha256=doc.content_sha256
 AND sp.start_cp<page_row.start_cp+hi AND sp.end_cp>page_row.start_cp+lo)
 THEN RAISE EXCEPTION 'source amount already assigned' USING ERRCODE='23505';END IF;
 IF (SELECT count(*) FROM vv_app.finance_revision WHERE tenant_id=t AND project_id=p)>=2000 THEN RAISE EXCEPTION 'financial revision quota' USING ERRCODE='54000';END IF;
 PERFORM vv_private.add_graph_span(t,p,s,v,pg,lo,hi,q,digest,a);
 INSERT INTO vv_app.finance_revision(tenant_id,project_id,id,revision,category,title,amount,currency,tax_basis,source_span_id,reviewer_id,release_on)
 VALUES(t,p,f,prior+1,cat,n,amt,'AUD',basis,s,a,release_date);
 INSERT INTO vv_app.finance_condition(tenant_id,project_id,finance_id,finance_revision,requirement_version_id)
 SELECT t,p,f,prior+1,x FROM unnest(ids) x;
 PERFORM vv_private.bump_graph(t,p);RETURN prior+1;
END $$;
CREATE FUNCTION vv_api.record_dispute(t uuid,p uuid,e uuid,f uuid,rev integer,kind text,instant timestamptz,details text,doc uuid,h uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.dispute_event%ROWTYPE;
BEGIN a:=vv_private.graph_lock(t,p);
 IF e IS NULL OR f IS NULL OR rev IS NULL OR rev<1 OR kind IS NULL OR kind NOT IN ('submission-asserted','delivery-asserted','receipt-asserted','acceptance-asserted','rejection-asserted','disputed','correction','payment-asserted','note') OR details IS NULL OR length(trim(details)) NOT BETWEEN 1 AND 2000 OR (instant IS NOT NULL AND (instant>clock_timestamp() OR instant<TIMESTAMPTZ '2000-01-01 00:00:00+00')) THEN RAISE EXCEPTION 'invalid event' USING ERRCODE='22023';END IF;
 IF NOT EXISTS(SELECT 1 FROM vv_app.finance_revision WHERE tenant_id=t AND project_id=p AND id=f AND revision=rev)
 OR (doc IS NOT NULL AND NOT EXISTS(SELECT 1 FROM vv_app.document_version WHERE tenant_id=t AND project_id=p AND id=doc AND reviewed_by IS NOT NULL AND scan_state='clean'))
 OR (h IS NOT NULL AND NOT EXISTS(SELECT 1 FROM vv_app.handover_draft WHERE tenant_id=t AND project_id=p AND id=h))
 THEN RAISE EXCEPTION 'event reference unavailable' USING ERRCODE='42501';END IF;
 SELECT * INTO old FROM vv_app.dispute_event WHERE tenant_id=t AND project_id=p AND id=e;
 IF FOUND THEN
 IF (old.finance_id,old.finance_revision,old.event_type,old.occurred_at,old.note,old.document_version_id,old.handover_id,old.actor_id) IS NOT DISTINCT FROM (f,rev,kind,instant,details,doc,h,a) THEN RETURN e;END IF;
 RAISE EXCEPTION 'event conflict' USING ERRCODE='23505';END IF;
 IF (SELECT count(*) FROM vv_app.dispute_event WHERE tenant_id=t AND project_id=p)>=5000 THEN RAISE EXCEPTION 'event quota' USING ERRCODE='54000';END IF;
 INSERT INTO vv_app.dispute_event(tenant_id,project_id,id,finance_id,finance_revision,event_type,occurred_at,note,document_version_id,handover_id,actor_id)
 VALUES(t,p,e,f,rev,kind,instant,details,doc,h,a);
 RETURN e;
END $$;
CREATE FUNCTION vv_api.financial_workspace(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_api AS $$
DECLARE w jsonb;items jsonb;events jsonb;history jsonb;local_date text;
BEGIN w:=vv_api.workspace(t,p);
 -- Use agreed project timezone, unknown timezone fails closed rather than guessing.
 SELECT to_char(clock_timestamp() AT TIME ZONE timezone,'YYYY-MM-DD') INTO local_date FROM vv_app.project WHERE tenant_id=t AND id=p;
 WITH latest AS(SELECT DISTINCT ON (id) * FROM vv_app.finance_revision WHERE tenant_id=t AND project_id=p ORDER BY id,revision DESC)
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',m.id,'revision',m.revision,'category',m.category,'title',m.title,'amount',m.amount,'currency',m.currency,'taxBasis',m.tax_basis,'releaseOn',m.release_on,'sourceId',d.id,'sourceSha256',d.content_sha256,'quote',s.quote,'start',s.start_cp,'end',s.end_cp,'sourceCurrent',NOT EXISTS(SELECT 1 FROM vv_app.document_version n WHERE n.tenant_id=t AND n.project_id=p AND n.document_id=d.document_id AND n.revision>d.revision),'conditions',coalesce((SELECT jsonb_agg(jsonb_build_object('id',r.requirement_id,'revision',r.revision) ORDER BY r.requirement_id) FROM vv_app.finance_condition c JOIN vv_app.requirement_version r ON (r.tenant_id,r.project_id,r.id)=(c.tenant_id,c.project_id,c.requirement_version_id) WHERE c.tenant_id=t AND c.project_id=p AND c.finance_id=m.id AND c.finance_revision=m.revision),'[]'::jsonb)) ORDER BY m.id),'[]'::jsonb) INTO items
 FROM latest m JOIN vv_app.source_span s ON (s.tenant_id,s.project_id,s.id)=(m.tenant_id,m.project_id,m.source_span_id)
 JOIN vv_app.document_version d ON (d.tenant_id,d.project_id,d.id)=(s.tenant_id,s.project_id,s.document_version_id);
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',e.id,'financeId',e.finance_id,'financeRevision',e.finance_revision,'type',e.event_type,'occurredAt',e.occurred_at,'recordedAt',e.recorded_at,'note',e.note,'sourceId',e.document_version_id,'sourceSha256',d.content_sha256,'handoverId',e.handover_id,'handoverSha256',h.sha256,'actorId',e.actor_id,'verification','member-asserted') ORDER BY coalesce(e.occurred_at,e.recorded_at),e.recorded_at,e.id),'[]'::jsonb) INTO events
 FROM vv_app.dispute_event e LEFT JOIN vv_app.document_version d ON (d.tenant_id,d.project_id,d.id)=(e.tenant_id,e.project_id,e.document_version_id)
 LEFT JOIN vv_app.handover_draft h ON (h.tenant_id,h.project_id,h.id)=(e.tenant_id,e.project_id,e.handover_id) WHERE e.tenant_id=t AND e.project_id=p;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',m.id,'revision',m.revision,'category',m.category,'title',m.title,'amount',m.amount,'currency',m.currency,'taxBasis',m.tax_basis,'releaseOn',m.release_on,'recordedAt',m.recorded_at,'reviewerId',m.reviewer_id,'sourceId',s.document_version_id,'quote',s.quote,'start',s.start_cp,'end',s.end_cp,'conditionVersionIds',coalesce((SELECT jsonb_agg(c.requirement_version_id ORDER BY c.requirement_version_id) FROM vv_app.finance_condition c WHERE c.tenant_id=t AND c.project_id=p AND c.finance_id=m.id AND c.finance_revision=m.revision),'[]'::jsonb)) ORDER BY m.recorded_at,m.id,m.revision),'[]'::jsonb) INTO history
 FROM vv_app.finance_revision m JOIN vv_app.source_span s ON (s.tenant_id,s.project_id,s.id)=(m.tenant_id,m.project_id,m.source_span_id) WHERE m.tenant_id=t AND m.project_id=p;
 RETURN jsonb_build_object('workspace',w,'localDate',local_date,'items',items,'events',events,'history',history);
END $$;
REVOKE ALL ON FUNCTION vv_api.save_finance(uuid,uuid,uuid,integer,text,text,text,text,uuid,uuid,integer,integer,integer,text,text,date,uuid[]),vv_api.record_dispute(uuid,uuid,uuid,uuid,integer,text,timestamptz,text,uuid,uuid),vv_api.financial_workspace(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.save_finance(uuid,uuid,uuid,integer,text,text,text,text,uuid,uuid,integer,integer,integer,text,text,date,uuid[]),vv_api.record_dispute(uuid,uuid,uuid,uuid,integer,text,timestamptz,text,uuid,uuid),vv_api.financial_workspace(uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
