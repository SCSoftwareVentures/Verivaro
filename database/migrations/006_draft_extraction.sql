BEGIN;
CREATE ROLE verivaro_parse_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
SET LOCAL ROLE verivaro_owner;
GRANT USAGE ON SCHEMA vv_api TO verivaro_parse_worker;
CREATE TABLE vv_private.extract_job(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,intent_id uuid NOT NULL,scan_id uuid NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','leased','complete','unsupported','dead')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease_token uuid UNIQUE,lease_until timestamptz,
 PRIMARY KEY(tenant_id,project_id,intent_id),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_app.quarantine_receipt(tenant_id,project_id,intent_id),
 FOREIGN KEY(tenant_id,project_id,scan_id) REFERENCES vv_app.scan_attempt(tenant_id,project_id,id),
 CHECK((state='leased')=(lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK(state='leased' OR (lease_token IS NULL AND lease_until IS NULL))
);
CREATE INDEX extraction_queue ON vv_private.extract_job(state,available_at,lease_until);
CREATE TABLE vv_app.extracted_text_draft(
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,intent_id uuid NOT NULL,
 source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 text_value text NOT NULL CHECK(octet_length(text_value) BETWEEN 1 AND 1048576),
 extractor_version text NOT NULL CHECK(extractor_version='utf8-exact-v1'),
 extracted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,intent_id),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_private.extract_job(tenant_id,project_id,intent_id),
 CHECK(encode(vv_crypto.digest(convert_to(text_value,'UTF8'),'sha256'),'hex')=source_sha256)
);
ALTER TABLE vv_private.extract_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_private.extract_job FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_private.extract_job TO verivaro_owner USING(true) WITH CHECK(true);
ALTER TABLE vv_app.extracted_text_draft ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_app.extracted_text_draft FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_app.extracted_text_draft TO verivaro_owner USING(true) WITH CHECK(true);
CREATE FUNCTION vv_private.enqueue_extract() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
BEGIN
 IF OLD.state='leased' AND NEW.state='complete' AND EXISTS(
 SELECT 1 FROM vv_app.scan_attempt s WHERE s.tenant_id=NEW.tenant_id AND s.project_id=NEW.project_id AND s.intent_id=NEW.intent_id AND s.id=OLD.lease_token AND s.outcome='clean')
 THEN INSERT INTO vv_private.extract_job(tenant_id,project_id,intent_id,scan_id)
 VALUES(NEW.tenant_id,NEW.project_id,NEW.intent_id,OLD.lease_token);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER scan_extract_job AFTER UPDATE OF state ON vv_private.scan_job FOR EACH ROW EXECUTE FUNCTION vv_private.enqueue_extract();
CREATE FUNCTION vv_api.claim_extract(token uuid)
RETURNS TABLE(tenant_id uuid,project_id uuid,intent_id uuid,object_key uuid,sha256 text,bytes bigint,media_type text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
BEGIN
 IF token IS NULL THEN RAISE EXCEPTION 'token required' USING ERRCODE='22023'; END IF;
 UPDATE vv_private.extract_job j SET state='dead',lease_token=NULL,lease_until=NULL
 WHERE j.state='leased' AND j.attempts=3 AND j.lease_until<=clock_timestamp();
 RETURN QUERY WITH candidate AS(
 SELECT j.tenant_id,j.project_id,j.intent_id FROM vv_private.extract_job j
 WHERE j.attempts<3 AND ((j.state='queued' AND j.available_at<=clock_timestamp()) OR (j.state='leased' AND j.lease_until<=clock_timestamp()))
 ORDER BY j.available_at,j.tenant_id,j.project_id,j.intent_id LIMIT 1 FOR UPDATE OF j SKIP LOCKED
 ), claimed AS(
 UPDATE vv_private.extract_job j SET state='leased',attempts=j.attempts+1,lease_token=token,lease_until=clock_timestamp()+interval '90 seconds'
 FROM candidate c WHERE (j.tenant_id,j.project_id,j.intent_id)=(c.tenant_id,c.project_id,c.intent_id)
 RETURNING j.tenant_id,j.project_id,j.intent_id
 ) SELECT r.tenant_id,r.project_id,r.intent_id,r.object_key,r.actual_sha256,r.actual_bytes,r.media_type
 FROM claimed c JOIN vv_app.quarantine_receipt r ON (r.tenant_id,r.project_id,r.intent_id)=(c.tenant_id,c.project_id,c.intent_id);
END $$;
CREATE FUNCTION vv_api.finish_extract(token uuid,result text,content text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_crypto AS $$
DECLARE j vv_private.extract_job%ROWTYPE;r vv_app.quarantine_receipt%ROWTYPE;next_state text;
BEGIN
 SELECT * INTO j FROM vv_private.extract_job WHERE lease_token=token AND state='leased' AND lease_until>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'lease unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT r FROM vv_app.quarantine_receipt WHERE (tenant_id,project_id,intent_id)=(j.tenant_id,j.project_id,j.intent_id);
 IF result='complete' AND r.media_type='text/plain' AND content IS NOT NULL AND octet_length(content)=r.actual_bytes AND r.actual_bytes<=1048576 AND encode(vv_crypto.digest(convert_to(content,'UTF8'),'sha256'),'hex')=r.actual_sha256 THEN
 INSERT INTO vv_app.extracted_text_draft(tenant_id,project_id,intent_id,source_sha256,text_value,extractor_version)
 VALUES(j.tenant_id,j.project_id,j.intent_id,r.actual_sha256,content,'utf8-exact-v1');next_state:='complete';
 ELSIF result='unsupported' AND content IS NULL AND (r.media_type<>'text/plain' OR r.actual_bytes>1048576) THEN next_state:='unsupported';
 ELSIF result='unavailable' AND content IS NULL THEN next_state:=CASE WHEN j.attempts=3 THEN 'dead' ELSE 'queued' END;
 ELSE RAISE EXCEPTION 'invalid extraction result' USING ERRCODE='22023'; END IF;
 UPDATE vv_private.extract_job SET state=next_state,lease_token=NULL,lease_until=NULL,available_at=clock_timestamp()+make_interval(secs=>15*j.attempts)
 WHERE (tenant_id,project_id,intent_id)=(j.tenant_id,j.project_id,j.intent_id);
 RETURN next_state;
END $$;
REVOKE ALL ON FUNCTION vv_private.enqueue_extract(),vv_api.claim_extract(uuid),vv_api.finish_extract(uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.claim_extract(uuid),vv_api.finish_extract(uuid,text,text) TO verivaro_parse_worker;
RESET ROLE;
COMMIT;
