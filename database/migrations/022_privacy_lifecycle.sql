BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE TABLE vv_app.retention_revision(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),
 retention_days integer NOT NULL CHECK(retention_days BETWEEN 1 AND 36500),legal_hold boolean NOT NULL,
 reason text NOT NULL CHECK(length(trim(reason)) BETWEEN 1 AND 500),actor_id uuid NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,revision),
 FOREIGN KEY(tenant_id,project_id) REFERENCES vv_app.project(tenant_id,id),
 FOREIGN KEY(tenant_id,project_id,actor_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_app.erasure_event(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,revision integer NOT NULL CHECK(revision>0),
 state text NOT NULL CHECK(state IN ('requested','approved-for-operator','cancelled')),
 reason text NOT NULL CHECK(length(trim(reason)) BETWEEN 1 AND 500),actor_id uuid NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 policy_revision integer NOT NULL CHECK(policy_revision>0),generation bigint NOT NULL CHECK(generation>=0),
 PRIMARY KEY(tenant_id,project_id,id,revision),
 FOREIGN KEY(tenant_id,project_id,policy_revision) REFERENCES vv_app.retention_revision(tenant_id,project_id,revision),
 FOREIGN KEY(tenant_id,project_id,actor_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE TABLE vv_private.privacy_export_audit(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,actor_id uuid NOT NULL,
 sha256 text NOT NULL CHECK(sha256~'^[0-9a-f]{64}$'),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,actor_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
DO $$ DECLARE rel regclass;BEGIN
 FOREACH rel IN ARRAY ARRAY['vv_app.retention_revision'::regclass,'vv_app.erasure_event'::regclass,'vv_private.privacy_export_audit'::regclass] LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',rel);EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',rel);
 EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING(true) WITH CHECK(true)',rel);
 END LOOP;
END $$;
CREATE FUNCTION vv_private.privacy_owner(t uuid,p uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
DECLARE a uuid;BEGIN
 a:=vv_private.release_owner(t,p);
 IF NOT EXISTS(SELECT 1 FROM vv_private.membership WHERE tenant_id=t AND actor_id=a AND tenant_role='owner' AND active) THEN RAISE EXCEPTION 'tenant and project owner required' USING ERRCODE='42501';END IF;
 RETURN a;
END $$;
CREATE FUNCTION vv_api.save_retention(t uuid,p uuid,prior integer,days integer,hold boolean,why text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.retention_revision%ROWTYPE;BEGIN
 a:=vv_private.privacy_owner(t,p);
 IF prior IS NULL OR prior<0 OR prior>=2147483647 OR days IS NULL OR days NOT BETWEEN 1 AND 36500 OR hold IS NULL OR why IS NULL OR length(trim(why)) NOT BETWEEN 1 AND 500 THEN RAISE EXCEPTION 'invalid retention policy' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.retention_revision WHERE tenant_id=t AND project_id=p ORDER BY revision DESC LIMIT 1;
 IF old.revision=prior+1 AND (old.retention_days,old.legal_hold,old.reason,old.actor_id) IS NOT DISTINCT FROM (days,hold,why,a) THEN RETURN old.revision;END IF;
 IF coalesce(old.revision,0)<>prior THEN RAISE EXCEPTION 'stale policy' USING ERRCODE='23505';END IF;
 IF prior>=1000 THEN RAISE EXCEPTION 'policy quota' USING ERRCODE='54000';END IF;
 INSERT INTO vv_app.retention_revision(tenant_id,project_id,revision,retention_days,legal_hold,reason,actor_id) VALUES(t,p,prior+1,days,hold,why,a);
 PERFORM vv_private.bump_graph(t,p);RETURN prior+1;
END $$;
CREATE FUNCTION vv_api.save_erasure_request(t uuid,p uuid,i uuid,prior integer,target_state text,policy_rev integer,why text) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;old vv_app.erasure_event%ROWTYPE;policy vv_app.retention_revision%ROWTYPE;g bigint;requester uuid;BEGIN
 a:=vv_private.privacy_owner(t,p);
 IF i IS NULL OR prior IS NULL OR prior NOT BETWEEN 0 AND 2 OR target_state IS NULL OR target_state NOT IN ('requested','approved-for-operator','cancelled') OR policy_rev IS NULL OR policy_rev<1 OR why IS NULL OR length(trim(why)) NOT BETWEEN 1 AND 500 THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='22023';END IF;
 SELECT * INTO old FROM vv_app.erasure_event WHERE tenant_id=t AND project_id=p AND id=i ORDER BY revision DESC LIMIT 1;
 IF old.revision=prior+1 AND (old.state,old.actor_id,old.policy_revision,old.reason) IS NOT DISTINCT FROM (target_state,a,policy_rev,why) THEN RETURN old.revision;END IF;
 IF coalesce(old.revision,0)<>prior THEN RAISE EXCEPTION 'stale request' USING ERRCODE='23505';END IF;
 SELECT * INTO policy FROM vv_app.retention_revision WHERE tenant_id=t AND project_id=p ORDER BY revision DESC LIMIT 1;
 IF policy.revision IS DISTINCT FROM policy_rev THEN RAISE EXCEPTION 'current policy required' USING ERRCODE='23505';END IF;
 SELECT generation INTO g FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;g:=coalesce(g,0);
 IF target_state='requested' THEN
 IF prior<>0 OR EXISTS(SELECT 1 FROM (SELECT DISTINCT ON(id) state FROM vv_app.erasure_event WHERE tenant_id=t AND project_id=p ORDER BY id,revision DESC) q WHERE q.state<>'cancelled') THEN RAISE EXCEPTION 'active erasure request exists' USING ERRCODE='23505';END IF;
 ELSIF target_state='approved-for-operator' THEN
 IF prior<>1 OR old.state<>'requested' OR old.actor_id=a OR policy.legal_hold OR old.policy_revision<>policy_rev OR old.generation<>g THEN RAISE EXCEPTION 'distinct owner, no hold and unchanged request required' USING ERRCODE='42501';END IF;
 -- Requester must still hold both owner authorities.
 requester:=old.actor_id;
 IF NOT EXISTS(SELECT 1 FROM vv_private.project_member pm JOIN vv_private.membership m ON (m.tenant_id,m.actor_id)=(pm.tenant_id,pm.actor_id) WHERE pm.tenant_id=t AND pm.project_id=p AND pm.actor_id=requester AND pm.active AND pm.role='owner' AND m.active AND m.tenant_role='owner' FOR SHARE OF pm,m) THEN RAISE EXCEPTION 'requester authority lost' USING ERRCODE='42501';END IF;
 ELSIF prior=0 OR old.state NOT IN ('requested','approved-for-operator') THEN RAISE EXCEPTION 'cancellation unavailable' USING ERRCODE='22023';END IF;
 IF (SELECT count(*) FROM vv_app.erasure_event WHERE tenant_id=t AND project_id=p)>=1000 THEN RAISE EXCEPTION 'request quota' USING ERRCODE='54000';END IF;
 IF target_state='approved-for-operator' THEN
 UPDATE vv_private.index_grant SET revoked_at=clock_timestamp(),revoked_by=a WHERE tenant_id=t AND project_id=p AND revoked_at IS NULL;
 PERFORM vv_private.bump_graph(t,p);
 SELECT generation INTO g FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;
 END IF;
 INSERT INTO vv_app.erasure_event(tenant_id,project_id,id,revision,state,reason,actor_id,policy_revision,generation) VALUES(t,p,i,prior+1,target_state,why,a,policy_rev,g);
 RETURN prior+1;
END $$;
-- Block new external shares while a project is approved for operator erasure review.
CREATE FUNCTION vv_private.erasure_grant_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_app AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM (SELECT DISTINCT ON(id) state FROM vv_app.erasure_event WHERE tenant_id=NEW.tenant_id AND project_id=NEW.project_id ORDER BY id,revision DESC) q WHERE q.state='approved-for-operator') THEN RAISE EXCEPTION 'sharing suspended pending erasure review' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER erasure_grant_guard BEFORE INSERT ON vv_private.index_grant FOR EACH ROW EXECUTE FUNCTION vv_private.erasure_grant_guard();
CREATE FUNCTION vv_api.privacy_status(t uuid,p uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;policy jsonb;events jsonb;g bigint;BEGIN
 a:=vv_private.privacy_owner(t,p);
 SELECT to_jsonb(r) INTO policy FROM vv_app.retention_revision r WHERE tenant_id=t AND project_id=p ORDER BY revision DESC LIMIT 1;
 SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.recorded_at,e.id,e.revision),'[]'::jsonb) INTO events FROM vv_app.erasure_event e WHERE tenant_id=t AND project_id=p;
 SELECT generation INTO g FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;
 RETURN jsonb_build_object('policy',policy,'events',events,'generation',coalesce(g,0)::text,'actorId',a,'automaticErasure',false,'operatorExecutionImplemented',false);
END $$;
-- Fixed project-only data inventory. No dynamic table or column names from caller.
CREATE FUNCTION vv_api.export_project_records(t uuid,p uuid,i uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto AS $$
DECLARE a uuid;item text;rows jsonb;body jsonb:='{}'::jsonb;total bigint:=0;payload text;digest text;BEGIN
 a:=vv_private.privacy_owner(t,p);
 IF i IS NULL THEN RAISE EXCEPTION 'export id required' USING ERRCODE='22023';END IF;
 IF EXISTS(SELECT 1 FROM vv_private.privacy_export_audit WHERE tenant_id=t AND project_id=p AND id=i) THEN RAISE EXCEPTION 'export ticket already used' USING ERRCODE='23505';END IF;
 IF (SELECT count(*) FROM vv_private.privacy_export_audit WHERE tenant_id=t AND project_id=p)>=1000 THEN RAISE EXCEPTION 'export quota' USING ERRCODE='54000';END IF;
 -- Enforce snapshot semantics for the multiple reads in this function.
 IF current_setting('transaction_isolation')<>'repeatable read' THEN RAISE EXCEPTION 'repeatable-read required' USING ERRCODE='22023';END IF;
 SELECT to_jsonb(pr) INTO rows FROM vv_app.project pr WHERE tenant_id=t AND id=p;
 body:=jsonb_build_object('project',rows);
 FOREACH item IN ARRAY ARRAY['document','document_version','source_span','requirement','requirement_version','evidence_link','upload_intent','quarantine_receipt','scan_attempt','extracted_text_draft','native_page_draft','requirement_decision','version_origin','version_page','requirement_origin','evidence_retirement','scope_checkpoint','prooflock_revision','rejection_event','handover_draft','finance_revision','finance_condition','dispute_event','index_release','original_release','contract_relation','milestone_capture','reviewer_original_audit','rejection_notice','correction_plan','retention_revision','erasure_event'] LOOP
 -- Preflight raw data size before aggregating (JSON overhead rechecked below).
 EXECUTE format('SELECT coalesce(sum(octet_length((to_jsonb(x)-''object_key''-''lease_token'')::text)),0) FROM vv_app.%I x WHERE tenant_id=$1 AND project_id=$2',item) INTO total USING t,p;
 IF total+octet_length(body::text)>8388608 THEN RAISE EXCEPTION 'export exceeds bounded snapshot; operator export required' USING ERRCODE='54000';END IF;
 EXECUTE format('SELECT coalesce(jsonb_agg(to_jsonb(x)-''object_key''-''lease_token'' ORDER BY (to_jsonb(x)-''object_key''-''lease_token'')::text),''[]''::jsonb) FROM vv_app.%I x WHERE tenant_id=$1 AND project_id=$2',item) INTO rows USING t,p;
 body:=body||jsonb_build_object(item,rows);
 END LOOP;
 SELECT coalesce(jsonb_agg(jsonb_build_object('actorId',actor_id,'role',role,'active',active,'version',version) ORDER BY actor_id),'[]'::jsonb) INTO rows FROM vv_private.project_member WHERE tenant_id=t AND project_id=p;
 body:=body||jsonb_build_object('projectMembers',rows);
 SELECT coalesce(jsonb_agg(to_jsonb(g)-'token_hash' ORDER BY g.id),'[]'::jsonb) INTO rows FROM vv_private.index_grant g WHERE tenant_id=t AND project_id=p;
 body:=body||jsonb_build_object('shareGrantMetadata',rows);
 payload:=jsonb_build_object('schema','verivaro-project-records-v1','exportId',i,'tenantId',t,'projectId',p,'asOf',statement_timestamp(),'containsOriginalBytes',false,'completeTenantExport',false,'records',body,'excluded','Original bytes, other projects, identity subjects, credential material, internal storage keys, worker queues and private security audit records; use authorised operator workflow for remaining data.')::text;
 IF octet_length(payload)>8388608 THEN RAISE EXCEPTION 'export exceeds bounded snapshot' USING ERRCODE='54000';END IF;
 digest:=encode(vv_crypto.digest(convert_to(payload,'UTF8'),'sha256'),'hex');
 INSERT INTO vv_private.privacy_export_audit(tenant_id,project_id,id,actor_id,sha256) VALUES(t,p,i,a,digest);
 RETURN jsonb_build_object('json',payload,'sha256',digest,'containsOriginalBytes',false,'completeTenantExport',false);
END $$;
REVOKE ALL ON FUNCTION vv_private.privacy_owner(uuid,uuid),vv_private.erasure_grant_guard(),vv_api.save_retention(uuid,uuid,integer,integer,boolean,text),vv_api.save_erasure_request(uuid,uuid,uuid,integer,text,integer,text),vv_api.privacy_status(uuid,uuid),vv_api.export_project_records(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.save_retention(uuid,uuid,integer,integer,boolean,text),vv_api.save_erasure_request(uuid,uuid,uuid,integer,text,integer,text),vv_api.privacy_status(uuid,uuid),vv_api.export_project_records(uuid,uuid,uuid) TO verivaro_runtime;
RESET ROLE;
COMMIT;
