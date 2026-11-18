BEGIN;
CREATE ROLE verivaro_recovery NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
SET LOCAL ROLE verivaro_owner;
GRANT USAGE ON SCHEMA vv_api TO verivaro_recovery;
CREATE TABLE vv_private.file_reservation (
 object_key uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL, intent_id uuid NOT NULL,
 actor_id uuid NOT NULL, expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','committed','abandoned')),
 next_check timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_app.upload_intent(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,actor_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id)
);
CREATE INDEX reservation_expiry ON vv_private.file_reservation(state,expires_at,next_check);
CREATE TABLE vv_private.scan_job (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, intent_id uuid NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','leased','complete','dead')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token uuid UNIQUE, lease_until timestamptz,
 PRIMARY KEY(tenant_id,project_id,intent_id),
 FOREIGN KEY(tenant_id,project_id,intent_id) REFERENCES vv_app.quarantine_receipt(tenant_id,project_id,intent_id),
 CHECK((state='leased')=(lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK(state='leased' OR (lease_token IS NULL AND lease_until IS NULL))
);
CREATE INDEX scan_queue ON vv_private.scan_job(state,available_at,lease_until);
ALTER TABLE vv_private.file_reservation ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_private.file_reservation FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_private.file_reservation TO verivaro_owner USING(true) WITH CHECK(true);
ALTER TABLE vv_private.scan_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE vv_private.scan_job FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON vv_private.scan_job TO verivaro_owner USING(true) WITH CHECK(true);
CREATE FUNCTION vv_api.reserve_file(t uuid,p uuid,u uuid,k uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
DECLARE a uuid;
BEGIN
 a:=vv_private.capture_actor(t,p);
 IF k IS NULL OR NOT EXISTS(SELECT 1 FROM vv_app.upload_intent WHERE tenant_id=t AND project_id=p AND id=u AND created_by=a)
 OR EXISTS(SELECT 1 FROM vv_app.quarantine_receipt WHERE tenant_id=t AND project_id=p AND intent_id=u)
 THEN RAISE EXCEPTION 'reservation denied' USING ERRCODE='42501'; END IF;
 INSERT INTO vv_private.file_reservation(object_key,tenant_id,project_id,intent_id,actor_id,expires_at)
 VALUES(k,t,p,u,a,clock_timestamp()+interval '10 minutes');
 RETURN k;
END $$;
-- Compatibility for legacy low-level trusted-worker receipt calls is preserved.
-- Any tracked object must match the reservation and may NEVER attach after abandonment/expiry.
CREATE FUNCTION vv_private.guard_reserved_receipt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
DECLARE r vv_private.file_reservation%ROWTYPE;
BEGIN
 SELECT * INTO r FROM vv_private.file_reservation WHERE object_key=NEW.object_key FOR UPDATE;
 IF FOUND AND (r.tenant_id<>NEW.tenant_id OR r.project_id<>NEW.project_id OR r.intent_id<>NEW.intent_id
 OR r.state='abandoned' OR (r.state='pending' AND r.expires_at<=clock_timestamp())) THEN
 RAISE EXCEPTION 'reservation unavailable' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER check_reservation BEFORE INSERT ON vv_app.quarantine_receipt FOR EACH ROW EXECUTE FUNCTION vv_private.guard_reserved_receipt();
CREATE FUNCTION vv_private.enqueue_scan() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
BEGIN
 UPDATE vv_private.file_reservation SET state='committed' WHERE object_key=NEW.object_key;
 INSERT INTO vv_private.scan_job(tenant_id,project_id,intent_id) VALUES(NEW.tenant_id,NEW.project_id,NEW.intent_id);
 RETURN NEW;
END $$;
CREATE TRIGGER receipt_scan_job AFTER INSERT ON vv_app.quarantine_receipt FOR EACH ROW EXECUTE FUNCTION vv_private.enqueue_scan();
-- Only exact reserved keys that can no longer be attached. Revisit abandoned keys to handle late/crashed writers.
CREATE FUNCTION vv_api.recover_files(batch integer) RETURNS TABLE(object_key uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
BEGIN
 IF batch IS NULL OR batch NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid batch' USING ERRCODE='22023'; END IF;
 RETURN QUERY WITH candidates AS(
 SELECT f.object_key FROM vv_private.file_reservation f
 WHERE ((f.state='pending' AND f.expires_at<=clock_timestamp()) OR (f.state='abandoned' AND f.next_check<=clock_timestamp()))
 AND NOT EXISTS(SELECT 1 FROM vv_app.quarantine_receipt r WHERE r.object_key=f.object_key)
 ORDER BY f.next_check,f.object_key LIMIT batch FOR UPDATE OF f SKIP LOCKED)
 UPDATE vv_private.file_reservation f SET state='abandoned',next_check=clock_timestamp()+interval '1 minute'
 FROM candidates c WHERE f.object_key=c.object_key RETURNING f.object_key;
END $$;
CREATE FUNCTION vv_api.claim_scan(token uuid)
RETURNS TABLE(tenant_id uuid,project_id uuid,intent_id uuid,object_key uuid,sha256 text,bytes bigint,media_type text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app AS $$
BEGIN
 IF token IS NULL THEN RAISE EXCEPTION 'token required' USING ERRCODE='22023'; END IF;
 UPDATE vv_private.scan_job j SET state='dead',lease_token=NULL,lease_until=NULL
 WHERE j.state='leased' AND j.attempts=5 AND j.lease_until<=clock_timestamp();
 RETURN QUERY WITH candidate AS(
 SELECT j.tenant_id,j.project_id,j.intent_id FROM vv_private.scan_job j
 WHERE j.attempts<5 AND ((j.state='queued' AND j.available_at<=clock_timestamp()) OR (j.state='leased' AND j.lease_until<=clock_timestamp()))
 ORDER BY j.available_at,j.tenant_id,j.project_id,j.intent_id LIMIT 1 FOR UPDATE OF j SKIP LOCKED
 ), claimed AS(
 UPDATE vv_private.scan_job j SET state='leased',attempts=j.attempts+1,lease_token=token,lease_until=clock_timestamp()+interval '90 seconds'
 FROM candidate c WHERE (j.tenant_id,j.project_id,j.intent_id)=(c.tenant_id,c.project_id,c.intent_id)
 RETURNING j.tenant_id,j.project_id,j.intent_id
 ) SELECT r.tenant_id,r.project_id,r.intent_id,r.object_key,r.actual_sha256,r.actual_bytes,r.media_type
 FROM claimed c JOIN vv_app.quarantine_receipt r ON (r.tenant_id,r.project_id,r.intent_id)=(c.tenant_id,c.project_id,c.intent_id);
END $$;
CREATE FUNCTION vv_api.finish_scan(token uuid,verdict text,scanner text,scanner_version text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private,vv_app,vv_api AS $$
DECLARE j vv_private.scan_job%ROWTYPE; r vv_app.quarantine_receipt%ROWTYPE; next_state text;
BEGIN
 SELECT * INTO j FROM vv_private.scan_job WHERE lease_token=token AND state='leased' AND lease_until>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'lease unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT r FROM vv_app.quarantine_receipt WHERE (tenant_id,project_id,intent_id)=(j.tenant_id,j.project_id,j.intent_id);
 PERFORM vv_api.record_scan(j.tenant_id,j.project_id,j.intent_id,token,r.object_key,r.actual_sha256,verdict,scanner,scanner_version);
 next_state:=CASE WHEN verdict<>'unavailable' THEN 'complete' WHEN j.attempts=5 THEN 'dead' ELSE 'queued' END;
 UPDATE vv_private.scan_job SET state=next_state,lease_token=NULL,lease_until=NULL,available_at=clock_timestamp()+make_interval(secs=>15*j.attempts)
 WHERE (tenant_id,project_id,intent_id)=(j.tenant_id,j.project_id,j.intent_id);
 RETURN next_state;
END $$;
REVOKE ALL ON FUNCTION vv_api.reserve_file(uuid,uuid,uuid,uuid),vv_api.recover_files(integer),vv_api.claim_scan(uuid),vv_api.finish_scan(uuid,text,text,text),vv_private.guard_reserved_receipt(),vv_private.enqueue_scan() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.reserve_file(uuid,uuid,uuid,uuid) TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION vv_api.recover_files(integer) TO verivaro_recovery;
GRANT EXECUTE ON FUNCTION vv_api.claim_scan(uuid),vv_api.finish_scan(uuid,text,text,text) TO verivaro_ingest_worker;
RESET ROLE;
COMMIT;
