\set ON_ERROR_STOP on
-- All migrations installed, synthetic harness only. Exact role/function allowlist denies new accidental exposure.
DO $$
DECLARE r text;f record;expected text[];actual boolean;tbl record;
BEGIN
 FOREACH r IN ARRAY ARRAY['verivaro_runtime','verivaro_signer','verivaro_ingest_worker','verivaro_parse_worker','verivaro_recovery','verivaro_capability','verivaro_erasure_operator','verivaro_portability_operator'] LOOP
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolcanlogin)) OR pg_has_role(r,'verivaro_owner','MEMBER') THEN RAISE EXCEPTION 'unsafe role %',r;END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname LIKE 'verivaro_%' AND rolname<>r AND pg_has_role(r,rolname,'MEMBER')) THEN RAISE EXCEPTION 'cross role inheritance %',r;END IF;
 expected:=CASE r
 WHEN 'verivaro_runtime' THEN ARRAY['vv_private.allowed_project','vv_api.create_document','vv_api.request_upload','vv_api.upload_status','vv_api.reserve_file','vv_api.review_pages','vv_api.decide_requirement','vv_api.promote_document','vv_api.promote_requirement','vv_api.link_evidence','vv_api.retire_evidence','vv_api.confirm_scope','vv_api.graph','vv_api.save_prooflock','vv_api.save_rejection','vv_api.import_rejection_notice','vv_api.save_correction_plan','vv_api.correction_queue','vv_api.workspace','vv_api.create_handover','vv_api.read_handover','vv_api.save_finance','vv_api.record_dispute','vv_api.financial_workspace','vv_api.approve_index','vv_api.grant_index','vv_api.revoke_index','vv_api.approve_originals','vv_api.grant_originals','vv_api.save_relation','vv_api.catalog','vv_api.reviewer_original','vv_api.request_milestone_upload','vv_api.privacy_status','vv_api.save_retention','vv_api.save_erasure_request','vv_api.export_project_records','vv_api.tenant_portability_inventory','vv_api.export_tenant_records']
 WHEN 'verivaro_signer' THEN ARRAY['vv_api.issue_context']
 WHEN 'verivaro_ingest_worker' THEN ARRAY['vv_api.record_quarantine','vv_api.record_scan','vv_api.claim_scan','vv_api.finish_scan']
 WHEN 'verivaro_parse_worker' THEN ARRAY['vv_api.claim_extract','vv_api.finish_extract','vv_api.finish_native_extract']
 WHEN 'verivaro_recovery' THEN ARRAY['vv_api.recover_files']
 WHEN 'verivaro_erasure_operator' THEN ARRAY['vv_api.prepare_project_erasure','vv_api.apply_project_erasure','vv_api.erasure_restore_status','vv_api.replay_project_erasure','vv_api.erasure_object_safety']
 WHEN 'verivaro_portability_operator' THEN ARRAY['vv_api.portability_original_inventory']
 WHEN 'verivaro_capability' THEN ARRAY['vv_api.read_shared_index','vv_api.read_original','vv_api.read_bundle_index'] END;
 FOR f IN SELECT p.oid,n.nspname||'.'||p.proname AS name,p.prosecdef,p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('vv_api','vv_private') LOOP
 actual:=has_function_privilege(r,f.oid,'EXECUTE');
 IF actual IS DISTINCT FROM (f.name=ANY(expected)) THEN RAISE EXCEPTION 'function privilege mismatch % %',r,f.name;END IF;
 IF actual AND (NOT f.prosecdef OR NOT EXISTS(SELECT 1 FROM unnest(f.proconfig) x WHERE x LIKE 'search_path=pg_catalog,%')) THEN RAISE EXCEPTION 'unsafe exposed function %',f.name;END IF;
 END LOOP;
 FOR tbl IN SELECT c.oid,n.nspname||'.'||c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('vv_private','vv_app') AND c.relkind='r' LOOP
 IF has_table_privilege(r,tbl.oid,'SELECT') IS DISTINCT FROM (r='verivaro_runtime' AND tbl.name='vv_app.project') OR has_table_privilege(r,tbl.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN RAISE EXCEPTION 'raw table privilege mismatch % %',r,tbl.name;END IF;
 END LOOP;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname IN ('vv_api','vv_private') AND a.grantee=0 AND a.privilege_type='EXECUTE') THEN RAISE EXCEPTION 'public function exposure';END IF;
 -- Reject overloads which might accidentally inherit a name-based allowlist.
 IF EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('vv_api','vv_private') GROUP BY n.nspname,p.proname HAVING count(*)>1) THEN RAISE EXCEPTION 'unreviewed overload';END IF;
END $$;
SELECT 'adversarial privilege matrix passed' AS result;
