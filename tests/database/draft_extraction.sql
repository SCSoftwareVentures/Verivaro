\set ON_ERROR_STOP on
BEGIN;
INSERT INTO vv_app.upload_intent(tenant_id,project_id,id,document_id,expected_sha256,expected_bytes,media_type,created_by)
VALUES('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000066','40000000-0000-0000-0000-000000000001',encode(vv_crypto.digest(convert_to('exact text','UTF8'),'sha256'),'hex'),10,'text/plain','10000000-0000-0000-0000-000000000001');
DO $$ DECLARE h text;BEGIN
 SELECT expected_sha256 INTO h FROM vv_app.upload_intent WHERE id='60000000-0000-0000-0000-000000000066';
 PERFORM vv_api.record_quarantine('00000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000066','70000000-0000-4000-8000-000000000066',h,10,'text/plain');
END $$;
SET LOCAL ROLE verivaro_parse_worker;
DO $$ BEGIN IF (SELECT count(*) FROM vv_api.claim_extract('80000000-0000-4000-8000-000000000066'))<>0 THEN RAISE EXCEPTION 'unscanned extraction';END IF;END $$;
RESET ROLE;
SET LOCAL ROLE verivaro_ingest_worker;
DO $$ DECLARE tok uuid:='80000000-0000-4000-8000-000000000067';BEGIN
 IF (SELECT count(*) FROM vv_api.claim_scan(tok))<>1 THEN RAISE EXCEPTION 'scan absent';END IF;
 IF vv_api.finish_scan(tok,'clean','synthetic','1')<>'complete' THEN RAISE EXCEPTION 'scan finish';END IF;
 BEGIN PERFORM vv_api.claim_extract(tok);RAISE EXCEPTION 'scanner parse authority';EXCEPTION WHEN insufficient_privilege THEN NULL;END;
END $$;
RESET ROLE;
SET LOCAL ROLE verivaro_parse_worker;
DO $$ DECLARE tok uuid:='80000000-0000-4000-8000-000000000068';BEGIN
 IF (SELECT count(*) FROM vv_api.claim_extract(tok))<>1 THEN RAISE EXCEPTION 'extract missing';END IF;
 IF (SELECT count(*) FROM vv_api.claim_extract('80000000-0000-4000-8000-000000000069'))<>0 THEN RAISE EXCEPTION 'double lease';END IF;
 BEGIN PERFORM vv_api.finish_extract(tok,'complete','wrong text');RAISE EXCEPTION 'digest bypass';EXCEPTION WHEN invalid_parameter_value THEN NULL;END;
 IF vv_api.finish_extract(tok,'complete','exact text')<>'complete' THEN RAISE EXCEPTION 'not complete';END IF;
 BEGIN PERFORM * FROM vv_app.extracted_text_draft;RAISE EXCEPTION 'raw draft access';EXCEPTION WHEN insufficient_privilege THEN NULL;END;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT text_value FROM vv_app.extracted_text_draft WHERE intent_id='60000000-0000-0000-0000-000000000066') IS DISTINCT FROM 'exact text' THEN RAISE EXCEPTION 'draft missing';END IF;
 IF (SELECT count(*) FROM vv_app.document_version)<>0 THEN RAISE EXCEPTION 'draft automatically approved';END IF;
END $$;
ROLLBACK;
SELECT 'bounded draft extraction verified' AS result;
