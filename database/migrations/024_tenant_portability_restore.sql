BEGIN;
SET LOCAL ROLE verivaro_owner;
CREATE FUNCTION vv_private.project_records_snapshot(t uuid,p uuid,i uuid,a uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto AS $$
DECLARE item text;rows jsonb;body jsonb:='{}'::jsonb;total bigint:=0;payload text;digest text;BEGIN
 IF NOT EXISTS(SELECT 1 FROM vv_private.project_member pm JOIN vv_private.membership m ON (pm.tenant_id,pm.actor_id)=(m.tenant_id,m.actor_id) WHERE pm.tenant_id=t AND pm.project_id=p AND pm.actor_id=a AND pm.active AND pm.role='owner' AND m.active AND m.tenant_role='owner') THEN RAISE EXCEPTION 'project owner required' USING ERRCODE='42501';END IF;
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
CREATE OR REPLACE FUNCTION vv_api.export_project_records(t uuid,p uuid,i uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
DECLARE a uuid;BEGIN a:=vv_private.privacy_owner(t,p);RETURN vv_private.project_records_snapshot(t,p,i,a);END $$;
-- One fixed transaction snapshot. No partial result and no cross-project owner bypass.
CREATE FUNCTION vv_api.export_tenant_records(t uuid,p uuid,i uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto AS $$
DECLARE a uuid;pr record;entries jsonb:='[]'::jsonb;part jsonb;payload text;d text;tenant_record jsonb;members jsonb;cnt integer;BEGIN
 a:=vv_private.privacy_owner(t,p);
 IF i IS NULL OR current_setting('transaction_isolation')<>'repeatable read' THEN RAISE EXCEPTION 'consistent export ticket required' USING ERRCODE='22023';END IF;
 -- Lock tenant inventory against project insert/delete and authority changes during export.
 LOCK TABLE vv_app.project,vv_private.project_member,vv_private.membership IN SHARE MODE;
 SELECT count(*) INTO cnt FROM vv_app.project WHERE tenant_id=t;
 IF cnt NOT BETWEEN 1 AND 20 THEN RAISE EXCEPTION 'operator archive required' USING ERRCODE='54000';END IF;
 IF EXISTS(SELECT 1 FROM vv_app.project pr WHERE pr.tenant_id=t AND NOT EXISTS(SELECT 1 FROM vv_private.project_member pm WHERE pm.tenant_id=t AND pm.project_id=pr.id AND pm.actor_id=a AND pm.active AND pm.role='owner')) THEN RAISE EXCEPTION 'all project owner grants required' USING ERRCODE='42501';END IF;
 SELECT to_jsonb(x) INTO tenant_record FROM vv_private.tenant x WHERE id=t;
 SELECT coalesce(jsonb_agg(jsonb_build_object('actorId',actor_id,'active',active,'role',tenant_role,'version',version) ORDER BY actor_id),'[]'::jsonb) INTO members FROM vv_private.membership WHERE tenant_id=t;
 FOR pr IN SELECT id FROM vv_app.project WHERE tenant_id=t ORDER BY id LOOP
 part:=vv_private.project_records_snapshot(t,pr.id,i,a);
 entries:=entries||jsonb_build_array(jsonb_build_object('projectId',pr.id,'sha256',part->>'sha256','json',part->>'json'));
 IF octet_length(entries::text)>16777216 THEN RAISE EXCEPTION 'tenant record limit exceeded; operator archive required' USING ERRCODE='54000';END IF;
 END LOOP;
 payload:=jsonb_build_object('schema','verivaro-tenant-records-v1','tenantId',t,'exportId',i,'asOf',statement_timestamp(),'projectCount',cnt,'tenant',tenant_record,'members',members,'projects',entries,'allProjectRecordsIncluded',true,'completeTenantExport',false,'containsOriginalBytes',false,'excluded','Original bytes, identity subjects, credentials, storage keys, private operational and security audit data; no partial project records returned.')::text;
 IF octet_length(payload)>16777216 THEN RAISE EXCEPTION 'tenant record limit exceeded' USING ERRCODE='54000';END IF;
 d:=encode(vv_crypto.digest(convert_to(payload,'UTF8'),'sha256'),'hex');
 RETURN jsonb_build_object('json',payload,'sha256',d,'allProjectRecordsIncluded',true,'completeTenantExport',false,'containsOriginalBytes',false);
END $$;
-- Restore replay is an offline operator action, never runtime. A trusted external
-- signed COMMIT witness must be verified by the operator adapter before SQL.
-- Snapshot may be older than approval, but must not be newer or have unknown keys.
CREATE FUNCTION vv_api.replay_project_erasure(t uuid,p uuid,i uuid,plan_sha text,ledger_sha text,original_generation bigint,object_keys uuid[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE rel regclass;existing vv_private.erasure_tombstone%ROWTYPE;g bigint;BEGIN
 IF t IS NULL OR p IS NULL OR i IS NULL OR plan_sha IS NULL OR plan_sha!~'^[0-9a-f]{64}$' OR ledger_sha IS NULL OR ledger_sha!~'^[0-9a-f]{64}$' OR original_generation IS NULL OR original_generation<0 OR object_keys IS NULL OR cardinality(object_keys)>4000 OR array_position(object_keys,NULL) IS NOT NULL OR cardinality(object_keys)<>(SELECT count(DISTINCT x) FROM unnest(object_keys) x) OR EXISTS(SELECT 1 FROM unnest(object_keys) x WHERE x::text!~'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') THEN RAISE EXCEPTION 'invalid replay parameters' USING ERRCODE='22023';END IF;
 PERFORM vv_private.erasure_lock_tables();
 SELECT * INTO existing FROM vv_private.erasure_tombstone WHERE tenant_id=t AND project_id=p;
 IF FOUND AND (existing.request_id,existing.plan_sha256,existing.ledger_sha256,existing.object_count) IS DISTINCT FROM (i,plan_sha,ledger_sha,cardinality(object_keys)) THEN RAISE EXCEPTION 'conflicting tombstone' USING ERRCODE='23505';END IF;
 IF EXISTS(SELECT 1 FROM vv_private.file_reservation f WHERE (f.tenant_id,f.project_id)<>(t,p) AND f.object_key=ANY(object_keys)) OR EXISTS(SELECT 1 FROM vv_app.quarantine_receipt q WHERE (q.tenant_id,q.project_id)<>(t,p) AND q.object_key=ANY(object_keys)) THEN RAISE EXCEPTION 'cross-project object collision' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM vv_private.file_reservation f WHERE (f.tenant_id,f.project_id)=(t,p) AND NOT f.object_key=ANY(object_keys)) OR EXISTS(SELECT 1 FROM vv_app.quarantine_receipt q WHERE (q.tenant_id,q.project_id)=(t,p) AND NOT q.object_key=ANY(object_keys)) THEN RAISE EXCEPTION 'unknown restored object; manual review required' USING ERRCODE='42501';END IF;
 SELECT generation INTO g FROM vv_app.scope_checkpoint WHERE tenant_id=t AND project_id=p;
 IF coalesce(g,0)>original_generation THEN RAISE EXCEPTION 'restored generation newer than erasure' USING ERRCODE='42501';END IF;
 -- A historical hold may have been superseded by the later committed erasure.
 -- Actual current legal-hold assessment belongs to the authorised restore operator.
 DELETE FROM vv_private.capability_audit ca USING vv_private.index_grant gr WHERE ca.grant_id=gr.id AND gr.tenant_id=t AND gr.project_id=p;
 FOREACH rel IN ARRAY vv_private.erasure_tables() LOOP EXECUTE format('DELETE FROM %s WHERE tenant_id=$1 AND project_id=$2',rel) USING t,p;END LOOP;
 DELETE FROM vv_app.project WHERE tenant_id=t AND id=p;
 INSERT INTO vv_private.erasure_tombstone(tenant_id,project_id,request_id,plan_sha256,ledger_sha256,object_count) VALUES(t,p,i,plan_sha,ledger_sha,cardinality(object_keys)) ON CONFLICT DO NOTHING;
 RETURN jsonb_build_object('projectRowsRemoved',true,'objectCount',cardinality(object_keys),'physicalMediaErasureCertified',false);
END $$;
CREATE FUNCTION vv_api.erasure_object_safety(t uuid,p uuid,object_keys uuid[]) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
 SELECT object_keys IS NOT NULL AND NOT EXISTS(SELECT 1 FROM vv_private.file_reservation f WHERE f.object_key=ANY(object_keys)) AND NOT EXISTS(SELECT 1 FROM vv_app.quarantine_receipt q WHERE q.object_key=ANY(object_keys))
$$;
REVOKE ALL ON FUNCTION vv_private.project_records_snapshot(uuid,uuid,uuid,uuid),vv_api.export_tenant_records(uuid,uuid,uuid),vv_api.replay_project_erasure(uuid,uuid,uuid,text,text,bigint,uuid[]),vv_api.erasure_object_safety(uuid,uuid,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.export_tenant_records(uuid,uuid,uuid) TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION vv_api.replay_project_erasure(uuid,uuid,uuid,text,text,bigint,uuid[]),vv_api.erasure_object_safety(uuid,uuid,uuid[]) TO verivaro_erasure_operator;
RESET ROLE;
COMMIT;
