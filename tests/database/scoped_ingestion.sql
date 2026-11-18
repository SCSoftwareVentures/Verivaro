\set ON_ERROR_STOP on
-- Run after foundation.sql so the synthetic tenants and memberships exist.
BEGIN;
SELECT pg_current_xact_id()::text AS tx \gset
SET LOCAL ROLE verivaro_signer;
SELECT context AS ctx,signature AS sig FROM vv_api.issue_context('synthetic','a','00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001',:'tx','30000000-0000-0000-0000-000000000001',floor(extract(epoch FROM statement_timestamp()))::bigint+60) \gset
DO $$ BEGIN
 BEGIN PERFORM secret FROM vv_private.context_key; RAISE EXCEPTION 'signer read secret'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM vv_api.issue_context('synthetic','a','00000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000003',pg_current_xact_id()::text,'30000000-0000-0000-0000-000000000001',floor(extract(epoch FROM statement_timestamp()))::bigint+60); RAISE EXCEPTION 'signed foreign membership'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
SET LOCAL ROLE verivaro_runtime;
SELECT set_config('verivaro.context',:'ctx',true),set_config('verivaro.signature',:'sig',true);
DO $$
DECLARE t uuid:='00000000-0000-0000-0000-000000000001'; p uuid:='20000000-0000-0000-0000-000000000001'; d uuid:='40000000-0000-0000-0000-000000000099'; u uuid:='60000000-0000-0000-0000-000000000001';
BEGIN
 IF vv_api.create_document(t,p,d,'Synthetic certificate')<>d OR vv_api.create_document(t,p,d,'Synthetic certificate')<>d THEN RAISE EXCEPTION 'document idempotency'; END IF;
 IF vv_api.request_upload(t,p,d,u,repeat('b',64),123,'application/pdf')<>u OR vv_api.request_upload(t,p,d,u,repeat('b',64),123,'application/pdf')<>u THEN RAISE EXCEPTION 'upload idempotency'; END IF;
 BEGIN PERFORM vv_api.create_document(t,p,d,'altered'); RAISE EXCEPTION 'document replay mismatch'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN PERFORM vv_api.request_upload(t,p,d,u,repeat('c',64),123,'application/pdf'); RAISE EXCEPTION 'upload replay mismatch'; EXCEPTION WHEN unique_violation THEN NULL; END;
 BEGIN PERFORM vv_api.request_upload(t,p,d,u,repeat('b',64),52428801,'application/pdf'); RAISE EXCEPTION 'size bypass'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
 BEGIN PERFORM vv_api.request_upload(t,p,d,u,repeat('b',64),123,'application/x-executable'); RAISE EXCEPTION 'type bypass'; EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
 BEGIN PERFORM vv_api.create_document(t,'20000000-0000-0000-0000-000000000002',d,'foreign'); RAISE EXCEPTION 'cross project write'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM vv_api.create_document('00000000-0000-0000-0000-000000000002','20000000-0000-0000-0000-000000000003',d,'foreign'); RAISE EXCEPTION 'cross tenant write'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM vv_api.issue_context('synthetic','b',t,p,pg_current_xact_id()::text,'30000000-0000-0000-0000-000000000001',9999999999); RAISE EXCEPTION 'runtime signer access'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN UPDATE vv_app.upload_intent SET state='pending'; RAISE EXCEPTION 'raw upload write'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM expected_sha256 FROM vv_app.upload_intent; RAISE EXCEPTION 'raw intent read'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM vv_app.upload_intent WHERE state='pending')<>1 THEN RAISE EXCEPTION 'unexpected intent count'; END IF;
 IF (SELECT count(*) FROM vv_app.document_version)<>0 THEN RAISE EXCEPTION 'metadata became evidence'; END IF;
END $$;
-- Viewer no longer authorised to capture, even with a still-valid signed membership claim.
UPDATE vv_private.project_member SET role='viewer' WHERE project_id='20000000-0000-0000-0000-000000000001';
SET LOCAL ROLE verivaro_runtime;
DO $$ BEGIN
 BEGIN PERFORM vv_api.create_document('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000098','viewer write'); RAISE EXCEPTION 'viewer write'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
ROLLBACK;
DO $$ BEGIN
 IF pg_has_role('verivaro_runtime','verivaro_signer','MEMBER') OR pg_has_role('verivaro_signer','verivaro_owner','MEMBER') THEN RAISE EXCEPTION 'role escalation'; END IF;
 IF has_function_privilege('verivaro_runtime','vv_api.issue_context(text,text,uuid,uuid,text,uuid,bigint)','EXECUTE') THEN RAISE EXCEPTION 'runtime signer privilege'; END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='verivaro_signer' AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcanlogin)) THEN RAISE EXCEPTION 'unsafe signer role'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('vv_app','vv_private') AND c.relkind='r' AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)) THEN RAISE EXCEPTION 'RLS coverage'; END IF;
END $$;
SELECT 'scoped ingestion checks passed' AS result;
