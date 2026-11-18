BEGIN;
CREATE ROLE verivaro_erasure_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
SET LOCAL ROLE verivaro_owner;
GRANT USAGE ON SCHEMA vv_api TO verivaro_erasure_operator;
-- Minimal durable marker deliberately has no FK to the erased project.
CREATE TABLE vv_private.erasure_tombstone(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,request_id uuid NOT NULL,
 plan_sha256 text NOT NULL CHECK(plan_sha256~'^[0-9a-f]{64}$'),
 ledger_sha256 text NOT NULL CHECK(ledger_sha256~'^[0-9a-f]{64}$'),
 object_count integer NOT NULL CHECK(object_count>=0),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id)
);
ALTER TABLE vv_private.erasure_tombstone ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_private.erasure_tombstone FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_private.erasure_tombstone TO verivaro_owner USING(true) WITH CHECK(true);
CREATE FUNCTION vv_private.erasure_no_recreate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM vv_private.erasure_tombstone WHERE tenant_id=NEW.tenant_id AND project_id=NEW.id) THEN RAISE EXCEPTION 'erased project cannot be recreated' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER erasure_no_recreate BEFORE INSERT ON vv_app.project FOR EACH ROW EXECUTE FUNCTION vv_private.erasure_no_recreate();
CREATE FUNCTION vv_private.erasure_tables() RETURNS regclass[]
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
 SELECT ARRAY['vv_app.correction_plan'::regclass,'vv_app.rejection_notice'::regclass,'vv_app.milestone_capture'::regclass,'vv_app.reviewer_original_audit'::regclass,'vv_app.finance_condition'::regclass,'vv_app.dispute_event'::regclass,'vv_app.finance_revision'::regclass,'vv_app.contract_relation'::regclass,'vv_app.original_release'::regclass,'vv_private.index_grant'::regclass,'vv_app.index_release'::regclass,'vv_app.handover_draft'::regclass,'vv_app.rejection_event'::regclass,'vv_app.prooflock_revision'::regclass,'vv_app.evidence_retirement'::regclass,'vv_app.evidence_link'::regclass,'vv_app.requirement_origin'::regclass,'vv_app.requirement_version'::regclass,'vv_app.requirement'::regclass,'vv_app.source_span'::regclass,'vv_app.version_page'::regclass,'vv_app.version_origin'::regclass,'vv_app.document_version'::regclass,'vv_app.requirement_decision'::regclass,'vv_app.native_page_draft'::regclass,'vv_app.extracted_text_draft'::regclass,'vv_private.extract_job'::regclass,'vv_private.scan_job'::regclass,'vv_app.scan_attempt'::regclass,'vv_app.quarantine_receipt'::regclass,'vv_private.file_reservation'::regclass,'vv_app.upload_intent'::regclass,'vv_app.document'::regclass,'vv_app.scope_checkpoint'::regclass,'vv_app.erasure_event'::regclass,'vv_app.retention_revision'::regclass,'vv_private.privacy_export_audit'::regclass,'vv_private.ingestion_audit'::regclass,'vv_private.project_member'::regclass]
$$;
-- Explicit list; schema additions that have a project scope fail closed until reviewed.
CREATE FUNCTION vv_private.erasure_lock_tables() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE rel regclass;listed regclass[]:=vv_private.erasure_tables();BEGIN
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('vv_app','vv_private') AND c.relkind='r'
 AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='project_id' AND NOT a.attisdropped)
 AND NOT(c.oid=ANY(listed)) AND c.oid<>'vv_private.erasure_tombstone'::regclass) THEN RAISE EXCEPTION 'unreviewed scoped table' USING ERRCODE='22023';END IF;
 -- Operator must quiesce application plus all workers before calling. Locks cover
 -- the complete reviewed inventory; no external writers can change the transaction.
 LOCK TABLE vv_app.project,vv_private.membership,vv_private.capability_audit,vv_private.erasure_tombstone IN SHARE ROW EXCLUSIVE MODE;
 FOREACH rel IN ARRAY listed LOOP EXECUTE format('LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE',rel);END LOOP;
END $$;
CREATE FUNCTION vv_api.prepare_project_erasure(t uuid,p uuid,i uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto AS $$
DECLARE e vv_app.erasure_event%ROWTYPE;req vv_app.erasure_event%ROWTYPE;policy vv_app.retention_revision%ROWTYPE;g bigint;keys jsonb;counts jsonb:='{}'::jsonb;rel regclass;n bigint;payload text;BEGIN
 IF t IS NULL OR p IS NULL OR i IS NULL THEN RAISE EXCEPTION 'scope required' USING ERRCODE='22023';END IF;
 PERFORM vv_private.erasure_lock_tables();
 IF NOT EXISTS(SELECT 1 FROM vv_app.project WHERE tenant_id=t AND id=p) THEN RAISE EXCEPTION 'project unavailable' USING ERRCODE='42501';END IF;
 SELECT * INTO e FROM vv_app.erasure_event WHERE tenant_id=t AND project_id=p AND id=i ORDER BY revision DESC LIMIT 1;
 SELECT * INTO req FROM vv_app.erasure_event WHERE tenant_id=t AND project_id=p AND id=i AND revision=1;
 SELECT * INTO policy FROM vv_app.retention_revision WHERE tenant_id=t AND project_id=p ORDER BY revision DESC LIMIT 1;
 SELECT generation INTO g FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;
 IF e.state IS DISTINCT FROM 'approved-for-operator' OR e.revision IS DISTINCT FROM 2 OR req.state IS DISTINCT FROM 'requested' OR e.actor_id IS NOT DISTINCT FROM req.actor_id OR policy.legal_hold IS DISTINCT FROM false OR e.policy_revision IS DISTINCT FROM policy.revision OR e.generation IS DISTINCT FROM g THEN RAISE EXCEPTION 'erasure approval stale or unavailable' USING ERRCODE='42501';END IF;
 IF (SELECT count(*) FROM vv_private.project_member pm JOIN vv_private.membership m ON (m.tenant_id,m.actor_id)=(pm.tenant_id,pm.actor_id) WHERE pm.tenant_id=t AND pm.project_id=p AND pm.active AND pm.role='owner' AND m.active AND m.tenant_role='owner' AND pm.actor_id IN (e.actor_id,req.actor_id))<>2 THEN RAISE EXCEPTION 'two current owners required' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM vv_private.file_reservation WHERE tenant_id=t AND project_id=p AND state='pending' AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM vv_private.scan_job WHERE tenant_id=t AND project_id=p AND state='leased') OR EXISTS(SELECT 1 FROM vv_private.extract_job WHERE tenant_id=t AND project_id=p AND state='leased') THEN RAISE EXCEPTION 'active file or job lease' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(k ORDER BY k),'[]'::jsonb) INTO keys FROM (SELECT object_key k FROM vv_app.quarantine_receipt WHERE tenant_id=t AND project_id=p UNION SELECT object_key FROM vv_private.file_reservation WHERE tenant_id=t AND project_id=p) x;
 IF jsonb_array_length(keys)>4000 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(keys) x WHERE x !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') THEN RAISE EXCEPTION 'invalid object inventory' USING ERRCODE='22023';END IF;
 IF EXISTS(SELECT 1 FROM vv_private.file_reservation f WHERE (f.tenant_id,f.project_id)<>(t,p) AND f.object_key IN (SELECT x::uuid FROM jsonb_array_elements_text(keys) x)) OR EXISTS(SELECT 1 FROM vv_app.quarantine_receipt q WHERE (q.tenant_id,q.project_id)<>(t,p) AND q.object_key IN (SELECT x::uuid FROM jsonb_array_elements_text(keys) x)) THEN RAISE EXCEPTION 'cross-scope object collision' USING ERRCODE='42501';END IF;
 FOREACH rel IN ARRAY vv_private.erasure_tables() LOOP
 EXECUTE format('SELECT count(*) FROM %s WHERE tenant_id=$1 AND project_id=$2',rel) INTO n USING t,p;counts:=counts||jsonb_build_object(rel::text,n);
 END LOOP;
 SELECT count(*) INTO n FROM vv_private.capability_audit ca JOIN vv_private.index_grant gr ON gr.id=ca.grant_id WHERE gr.tenant_id=t AND gr.project_id=p;
 counts:=counts||jsonb_build_object('vv_private.capability_audit',n);
 payload:=jsonb_build_object('schema','verivaro-erasure-plan-v1','tenantId',t,'projectId',p,'requestId',i,'policyRevision',policy.revision,'generation',g::text,'objectKeys',keys,'rowCounts',counts)::text;
 RETURN jsonb_build_object('json',payload,'sha256',encode(vv_crypto.digest(convert_to(payload,'UTF8'),'sha256'),'hex'));
END $$;
-- No application access. Operator must durably write a verified external signed ledger
-- BEFORE this transaction commits. Exact recheck of the prepared plan is mandatory.
CREATE FUNCTION vv_api.apply_project_erasure(t uuid,p uuid,i uuid,expected_sha text,ledger_sha text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_api AS $$
DECLARE plan jsonb;rel regclass;n integer;BEGIN
 IF expected_sha IS NULL OR expected_sha!~'^[0-9a-f]{64}$' OR ledger_sha IS NULL OR ledger_sha!~'^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'signed ledger reference required' USING ERRCODE='22023';END IF;
 plan:=vv_api.prepare_project_erasure(t,p,i);
 IF plan->>'sha256' IS DISTINCT FROM expected_sha THEN RAISE EXCEPTION 'plan changed' USING ERRCODE='23505';END IF;
 n:=jsonb_array_length((plan->>'json')::jsonb->'objectKeys');
 DELETE FROM vv_private.capability_audit ca USING vv_private.index_grant gr WHERE ca.grant_id=gr.id AND gr.tenant_id=t AND gr.project_id=p;
 FOREACH rel IN ARRAY vv_private.erasure_tables() LOOP EXECUTE format('DELETE FROM %s WHERE tenant_id=$1 AND project_id=$2',rel) USING t,p;END LOOP;
 DELETE FROM vv_app.project WHERE tenant_id=t AND id=p;
 INSERT INTO vv_private.erasure_tombstone(tenant_id,project_id,request_id,plan_sha256,ledger_sha256,object_count) VALUES(t,p,i,expected_sha,ledger_sha,n);
 RETURN jsonb_build_object('projectRowsRemoved',true,'objectCount',n,'physicalMediaErasureCertified',false);
END $$;
CREATE FUNCTION vv_api.erasure_restore_status(t uuid,p uuid,i uuid,plan_sha text,ledger_sha text) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
 SELECT NOT EXISTS(SELECT 1 FROM vv_app.project WHERE tenant_id=t AND id=p) AND EXISTS(SELECT 1 FROM vv_private.erasure_tombstone e WHERE (e.tenant_id,e.project_id,e.request_id,e.plan_sha256,e.ledger_sha256)=(t,p,i,plan_sha,ledger_sha))
$$;
-- Tenant inventory: owners can discover explicitly inaccessible projects, but cannot
-- read them without each project owner grant. No single-project token bypass.
CREATE FUNCTION vv_api.tenant_portability_inventory(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;items jsonb;BEGIN a:=vv_private.privacy_owner(t,p);
 IF (SELECT count(*) FROM vv_app.project WHERE tenant_id=t)>1000 THEN RAISE EXCEPTION 'operator inventory required' USING ERRCODE='54000';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('projectId',pr.id,'eligible',coalesce(pm.active AND pm.role='owner',false),'name',CASE WHEN pm.active AND pm.role='owner' THEN pr.name END) ORDER BY pr.id),'[]'::jsonb) INTO items
 FROM vv_app.project pr LEFT JOIN vv_private.project_member pm ON (pm.tenant_id,pm.project_id,pm.actor_id)=(pr.tenant_id,pr.id,a) WHERE pr.tenant_id=t;
 RETURN jsonb_build_object('tenantId',t,'projects',items,'completeTenantExport',false,'originalBytesIncluded',false);
END $$;
REVOKE ALL ON FUNCTION vv_private.erasure_no_recreate(),vv_private.erasure_tables(),vv_private.erasure_lock_tables(),vv_api.prepare_project_erasure(uuid,uuid,uuid),vv_api.apply_project_erasure(uuid,uuid,uuid,text,text),vv_api.erasure_restore_status(uuid,uuid,uuid,text,text),vv_api.tenant_portability_inventory(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.prepare_project_erasure(uuid,uuid,uuid),vv_api.apply_project_erasure(uuid,uuid,uuid,text,text),vv_api.erasure_restore_status(uuid,uuid,uuid,text,text) TO verivaro_erasure_operator;
GRANT EXECUTE ON FUNCTION vv_api.tenant_portability_inventory(uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
