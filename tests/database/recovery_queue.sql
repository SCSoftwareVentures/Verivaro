\set ON_ERROR_STOP on
BEGIN;
INSERT INTO vv_app.upload_intent(tenant_id,project_id,id,document_id,expected_sha256,expected_bytes,media_type,created_by)
VALUES('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000055','40000000-0000-0000-0000-000000000001',repeat('d',64),123,'application/pdf','10000000-0000-0000-0000-000000000001');
INSERT INTO vv_private.file_reservation(object_key,tenant_id,project_id,intent_id,actor_id,expires_at)
SELECT k,'00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000055','10000000-0000-0000-0000-000000000001',clock_timestamp()+dur
FROM (VALUES ('70000000-0000-4000-8000-000000000055'::uuid,interval '5 minutes'),('70000000-0000-4000-8000-000000000056'::uuid,interval '-1 minute')) v(k,dur);
SET LOCAL ROLE verivaro_recovery;
DO $$ BEGIN
 IF (SELECT array_agg(object_key) FROM vv_api.recover_files(10)) IS DISTINCT FROM ARRAY['70000000-0000-4000-8000-000000000056'::uuid] THEN RAISE EXCEPTION 'unsafe recovery selection'; END IF;
 BEGIN PERFORM * FROM vv_private.file_reservation; RAISE EXCEPTION 'raw recovery read'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
SET LOCAL ROLE verivaro_ingest_worker;
DO $$ DECLARE t uuid:='00000000-0000-0000-0000-000000000001'; p uuid:='20000000-0000-0000-0000-000000000001'; u uuid:='60000000-0000-0000-0000-000000000055'; token uuid:='80000000-0000-4000-8000-000000000055'; BEGIN
 BEGIN PERFORM vv_api.record_quarantine(t,p,u,'70000000-0000-4000-8000-000000000056',repeat('d',64),123,'application/pdf'); RAISE EXCEPTION 'abandoned object attached'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM vv_api.record_quarantine(t,p,u,'70000000-0000-4000-8000-000000000055',repeat('d',64),123,'application/pdf');
 IF (SELECT count(*) FROM vv_api.claim_scan(token))<>1 THEN RAISE EXCEPTION 'scan job absent'; END IF;
 IF (SELECT count(*) FROM vv_api.claim_scan('80000000-0000-4000-8000-000000000056'))<>0 THEN RAISE EXCEPTION 'double lease'; END IF;
 BEGIN PERFORM vv_api.finish_scan('80000000-0000-4000-8000-000000000056','clean','synthetic','1'); RAISE EXCEPTION 'forged lease'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF vv_api.finish_scan(token,'unavailable',NULL,NULL)<>'queued' THEN RAISE EXCEPTION 'retry missing'; END IF;
END $$;
RESET ROLE;
UPDATE vv_private.scan_job SET available_at=clock_timestamp()-interval '1 minute' WHERE intent_id='60000000-0000-0000-0000-000000000055';
SET LOCAL ROLE verivaro_ingest_worker;
DO $$ DECLARE token uuid:='80000000-0000-4000-8000-000000000057'; BEGIN
 IF (SELECT count(*) FROM vv_api.claim_scan(token))<>1 THEN RAISE EXCEPTION 'retry not leased'; END IF;
 IF vv_api.finish_scan(token,'clean','synthetic','1')<>'complete' THEN RAISE EXCEPTION 'scan did not complete'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT state FROM vv_private.file_reservation WHERE object_key='70000000-0000-4000-8000-000000000055')<>'committed' THEN RAISE EXCEPTION 'receipt state missing'; END IF;
 IF (SELECT count(*) FROM vv_app.document_version)<>0 THEN RAISE EXCEPTION 'scan released evidence'; END IF;
 IF (SELECT attempts FROM vv_private.scan_job WHERE intent_id='60000000-0000-0000-0000-000000000055')<>2 THEN RAISE EXCEPTION 'attempt count'; END IF;
END $$;
ROLLBACK;
SELECT 'durable job and file recovery verified' AS result;
