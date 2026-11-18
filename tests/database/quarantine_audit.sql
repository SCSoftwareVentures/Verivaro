\set ON_ERROR_STOP on
BEGIN;
-- Existing foundation fixture supplies tenant A / project A1 / document.
INSERT INTO vv_app.upload_intent(tenant_id,project_id,id,document_id,expected_sha256,expected_bytes,media_type,created_by)
VALUES('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000077','40000000-0000-0000-0000-000000000001',repeat('d',64),123,'application/pdf','10000000-0000-0000-0000-000000000001');
SET LOCAL ROLE verivaro_ingest_worker;
DO $$
DECLARE t uuid:='00000000-0000-0000-0000-000000000001'; p uuid:='20000000-0000-0000-0000-000000000001'; u uuid:='60000000-0000-0000-0000-000000000077'; k uuid:='70000000-0000-4000-8000-000000000001'; s uuid:='80000000-0000-0000-0000-000000000001';
BEGIN
 BEGIN PERFORM vv_api.record_quarantine(t,p,u,k,repeat('e',64),123,'application/pdf'); RAISE EXCEPTION 'hash mismatch accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM vv_api.record_quarantine(t,p,u,k,repeat('d',64),124,'application/pdf'); RAISE EXCEPTION 'size mismatch accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM vv_api.record_scan(t,p,u,s,k,repeat('d',64),'clean','synthetic','1'); RAISE EXCEPTION 'scan before receipt'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF vv_api.record_quarantine(t,p,u,k,repeat('d',64),123,'application/pdf')<>u OR vv_api.record_quarantine(t,p,u,k,repeat('d',64),123,'application/pdf')<>u THEN RAISE EXCEPTION 'receipt replay'; END IF;
 BEGIN PERFORM vv_api.record_quarantine(t,p,u,'70000000-0000-4000-8000-000000000002',repeat('d',64),123,'application/pdf'); RAISE EXCEPTION 'conflicting receipt'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN PERFORM vv_api.record_scan(t,p,u,s,k,repeat('e',64),'clean','synthetic','1'); RAISE EXCEPTION 'wrong digest scanned'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM vv_api.record_scan(t,'20000000-0000-0000-0000-000000000002',u,s,k,repeat('d',64),'clean','synthetic','1'); RAISE EXCEPTION 'wrong scope scanned'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM vv_api.record_scan(t,p,u,s,k,repeat('d',64),'clean',NULL,NULL); RAISE EXCEPTION 'missing engine accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 IF vv_api.record_scan(t,p,u,s,k,repeat('d',64),'unavailable',NULL,NULL)<>s OR vv_api.record_scan(t,p,u,s,k,repeat('d',64),'unavailable',NULL,NULL)<>s THEN RAISE EXCEPTION 'scan replay'; END IF;
 BEGIN PERFORM vv_api.record_scan(t,p,u,s,k,repeat('d',64),'clean','synthetic','1'); RAISE EXCEPTION 'scan rewritten'; EXCEPTION WHEN unique_violation THEN NULL; END;
 PERFORM vv_api.record_scan(t,p,u,'80000000-0000-0000-0000-000000000002',k,repeat('d',64),'clean','synthetic','1');
 BEGIN PERFORM vv_api.create_document(t,p,u,'forbidden'); RAISE EXCEPTION 'worker document creation'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM secret FROM vv_private.context_key; RAISE EXCEPTION 'worker keys exposed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN DELETE FROM vv_private.ingestion_audit; RAISE EXCEPTION 'worker audit tamper'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
SET LOCAL ROLE verivaro_runtime;
DO $$ BEGIN
 BEGIN PERFORM vv_api.record_quarantine(NULL,NULL,NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'runtime receipt authority'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM vv_api.record_scan(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL); RAISE EXCEPTION 'runtime scan authority'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM * FROM vv_app.quarantine_receipt; RAISE EXCEPTION 'raw blob metadata read'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM * FROM vv_private.ingestion_audit; RAISE EXCEPTION 'raw audit read'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM vv_app.quarantine_receipt)<>1 OR (SELECT count(*) FROM vv_app.scan_attempt)<>2 THEN RAISE EXCEPTION 'duplicate metadata'; END IF;
 IF (SELECT array_agg(action ORDER BY event_id) FROM vv_private.ingestion_audit WHERE project_id='20000000-0000-0000-0000-000000000001' AND object_id IN ('60000000-0000-0000-0000-000000000077','80000000-0000-0000-0000-000000000001','80000000-0000-0000-0000-000000000002')) IS DISTINCT FROM ARRAY['upload_requested','quarantine_recorded','scan_unavailable','scan_clean']::text[] THEN RAISE EXCEPTION 'audit missing or duplicated'; END IF;
 IF (SELECT count(*) FROM vv_app.document_version)<>0 THEN RAISE EXCEPTION 'scan bypassed evidence release'; END IF;
 IF pg_has_role('verivaro_runtime','verivaro_ingest_worker','MEMBER') OR pg_has_role('verivaro_ingest_worker','verivaro_owner','MEMBER') OR pg_has_role('verivaro_ingest_worker','verivaro_signer','MEMBER') THEN RAISE EXCEPTION 'worker role escalation'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('vv_app','vv_private') AND c.relkind='r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)) THEN RAISE EXCEPTION 'RLS coverage'; END IF;
END $$;
ROLLBACK;
SELECT 'quarantine metadata and audit checks passed' AS result;
