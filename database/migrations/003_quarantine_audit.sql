-- Quarantine metadata and audit events only; no release-to-evidence pathway.
BEGIN;
CREATE ROLE verivaro_ingest_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
SET LOCAL ROLE verivaro_owner;
GRANT USAGE ON SCHEMA vv_api TO verivaro_ingest_worker;
ALTER TABLE vv_app.upload_intent ADD UNIQUE(tenant_id,project_id,id,expected_sha256,expected_bytes,media_type);
CREATE TABLE vv_app.quarantine_receipt (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, intent_id uuid NOT NULL,
 object_key uuid NOT NULL UNIQUE, actual_sha256 text NOT NULL, actual_bytes bigint NOT NULL, media_type text NOT NULL,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,intent_id),
 UNIQUE(tenant_id,project_id,intent_id,actual_sha256),
 FOREIGN KEY(tenant_id,project_id,intent_id,actual_sha256,actual_bytes,media_type)
 REFERENCES vv_app.upload_intent(tenant_id,project_id,id,expected_sha256,expected_bytes,media_type)
);
CREATE TABLE vv_app.scan_attempt (
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, id uuid NOT NULL, intent_id uuid NOT NULL,
 scanned_sha256 text NOT NULL, outcome text NOT NULL CHECK(outcome IN ('clean','rejected','unavailable')),
 engine text, engine_version text, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,intent_id,scanned_sha256)
 REFERENCES vv_app.quarantine_receipt(tenant_id,project_id,intent_id,actual_sha256),
 CHECK((outcome='unavailable' AND engine IS NULL AND engine_version IS NULL) OR
 (outcome IN ('clean','rejected') AND engine IS NOT NULL AND engine_version IS NOT NULL
 AND length(trim(engine)) BETWEEN 1 AND 80 AND length(trim(engine_version)) BETWEEN 1 AND 80))
);
CREATE TABLE vv_private.ingestion_audit (
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL, project_id uuid NOT NULL, object_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('document_created','upload_requested','quarantine_recorded','scan_clean','scan_rejected','scan_unavailable')),
 actor_id uuid, actor_kind text NOT NULL CHECK(actor_kind IN ('member','worker')),
 logged_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES vv_app.project(tenant_id,id),
 FOREIGN KEY(tenant_id,project_id,actor_id) REFERENCES vv_private.project_member(tenant_id,project_id,actor_id),
 CHECK((actor_kind='member')=(actor_id IS NOT NULL))
);
CREATE INDEX audit_scope ON vv_private.ingestion_audit(tenant_id,project_id,event_id);
CREATE INDEX scan_intent ON vv_app.scan_attempt(tenant_id,project_id,intent_id);
DO $$
DECLARE t regclass;
BEGIN
 FOREACH t IN ARRAY ARRAY['vv_app.quarantine_receipt'::regclass,'vv_app.scan_attempt'::regclass,'vv_private.ingestion_audit'::regclass] LOOP
 EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY owner_only ON %s TO verivaro_owner USING(true) WITH CHECK(true)',t);
 END LOOP;
END $$;
-- Audit insert is part of the same transaction. No contents, names, digests or keys logged.
CREATE FUNCTION vv_private.audit_ingestion() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_private AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'vv_app' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'invalid audit trigger'; END IF;
 CASE TG_TABLE_NAME
 WHEN 'document' THEN INSERT INTO vv_private.ingestion_audit(tenant_id,project_id,object_id,action,actor_id,actor_kind)
 VALUES(NEW.tenant_id,NEW.project_id,NEW.id,'document_created',NEW.created_by,'member');
 WHEN 'upload_intent' THEN INSERT INTO vv_private.ingestion_audit(tenant_id,project_id,object_id,action,actor_id,actor_kind)
 VALUES(NEW.tenant_id,NEW.project_id,NEW.id,'upload_requested',NEW.created_by,'member');
 WHEN 'quarantine_receipt' THEN INSERT INTO vv_private.ingestion_audit(tenant_id,project_id,object_id,action,actor_kind)
 VALUES(NEW.tenant_id,NEW.project_id,NEW.intent_id,'quarantine_recorded','worker');
 WHEN 'scan_attempt' THEN INSERT INTO vv_private.ingestion_audit(tenant_id,project_id,object_id,action,actor_kind)
 VALUES(NEW.tenant_id,NEW.project_id,NEW.id,'scan_'||NEW.outcome,'worker');
 ELSE RAISE EXCEPTION 'unexpected audit table';
 END CASE;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION vv_private.audit_ingestion() FROM PUBLIC;
CREATE TRIGGER audit_document AFTER INSERT ON vv_app.document FOR EACH ROW EXECUTE FUNCTION vv_private.audit_ingestion();
CREATE TRIGGER audit_intent AFTER INSERT ON vv_app.upload_intent FOR EACH ROW EXECUTE FUNCTION vv_private.audit_ingestion();
CREATE TRIGGER audit_receipt AFTER INSERT ON vv_app.quarantine_receipt FOR EACH ROW EXECUTE FUNCTION vv_private.audit_ingestion();
CREATE TRIGGER audit_scan AFTER INSERT ON vv_app.scan_attempt FOR EACH ROW EXECUTE FUNCTION vv_private.audit_ingestion();
-- Trusted worker reports an already verified persisted object; never expose to an HTTP caller.
CREATE FUNCTION vv_api.record_quarantine(t uuid,p uuid,u uuid,k uuid,sha text,n bigint,mime text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_app AS $$
DECLARE r vv_app.quarantine_receipt%ROWTYPE;
BEGIN
 IF t IS NULL OR p IS NULL OR u IS NULL OR k IS NULL OR sha IS NULL OR n IS NULL OR mime IS NULL OR NOT EXISTS(
 SELECT 1 FROM vv_app.upload_intent WHERE tenant_id=t AND project_id=p AND id=u AND expected_sha256=sha AND expected_bytes=n AND media_type=mime)
 THEN RAISE EXCEPTION 'receipt denied' USING ERRCODE='42501'; END IF;
 INSERT INTO vv_app.quarantine_receipt(tenant_id,project_id,intent_id,object_key,actual_sha256,actual_bytes,media_type)
 VALUES(t,p,u,k,sha,n,mime) ON CONFLICT (tenant_id,project_id,intent_id) DO NOTHING;
 SELECT * INTO r FROM vv_app.quarantine_receipt WHERE tenant_id=t AND project_id=p AND intent_id=u;
 IF r.object_key IS DISTINCT FROM k OR r.actual_sha256 IS DISTINCT FROM sha OR r.actual_bytes IS DISTINCT FROM n OR r.media_type IS DISTINCT FROM mime THEN
 RAISE EXCEPTION 'receipt conflict' USING ERRCODE='23505'; END IF;
 RETURN u;
END $$;
CREATE FUNCTION vv_api.record_scan(t uuid,p uuid,u uuid,s uuid,k uuid,sha text,result text,scanner text,scanner_version text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,vv_app AS $$
DECLARE r vv_app.scan_attempt%ROWTYPE;
BEGIN
 IF s IS NULL OR k IS NULL OR sha IS NULL OR result IS NULL OR NOT EXISTS(
 SELECT 1 FROM vv_app.quarantine_receipt WHERE tenant_id=t AND project_id=p AND intent_id=u AND object_key=k AND actual_sha256=sha)
 THEN RAISE EXCEPTION 'scan denied' USING ERRCODE='42501'; END IF;
 INSERT INTO vv_app.scan_attempt(tenant_id,project_id,id,intent_id,scanned_sha256,outcome,engine,engine_version)
 VALUES(t,p,s,u,sha,result,scanner,scanner_version) ON CONFLICT (tenant_id,project_id,id) DO NOTHING;
 SELECT * INTO r FROM vv_app.scan_attempt WHERE tenant_id=t AND project_id=p AND id=s;
 IF r.intent_id IS DISTINCT FROM u OR r.scanned_sha256 IS DISTINCT FROM sha OR r.outcome IS DISTINCT FROM result OR r.engine IS DISTINCT FROM scanner OR r.engine_version IS DISTINCT FROM scanner_version THEN
 RAISE EXCEPTION 'scan conflict' USING ERRCODE='23505'; END IF;
 RETURN s;
END $$;
REVOKE ALL ON FUNCTION vv_api.record_quarantine(uuid,uuid,uuid,uuid,text,bigint,text),vv_api.record_scan(uuid,uuid,uuid,uuid,uuid,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vv_api.record_quarantine(uuid,uuid,uuid,uuid,text,bigint,text),vv_api.record_scan(uuid,uuid,uuid,uuid,uuid,text,text,text,text) TO verivaro_ingest_worker;
RESET ROLE;
COMMIT;
