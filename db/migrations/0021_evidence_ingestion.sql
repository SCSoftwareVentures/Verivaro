BEGIN;
CREATE ROLE verivaro_evidence_ingestor NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA verivaro_ingestion;
REVOKE ALL ON SCHEMA verivaro_ingestion FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_ingestion TO verivaro_evidence_ingestor;
CREATE TABLE verivaro_private.evidence_objects(
 evidence_id uuid PRIMARY KEY REFERENCES verivaro.evidence(id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,actor_id uuid NOT NULL,session_id uuid NOT NULL,request_id uuid NOT NULL,
 sha256 text NOT NULL CHECK(sha256~'^[0-9a-f]{64}$'),
 bytes integer NOT NULL CHECK(bytes BETWEEN 1 AND 262144),
 key_id text NOT NULL CHECK(key_id~'^[a-z][a-z0-9_-]{0,31}$'),
 envelope bytea NOT NULL CHECK(octet_length(envelope)=bytes+28),
 cipher_digest bytea NOT NULL CHECK(octet_length(cipher_digest)=32),
 scan_policy text NOT NULL CHECK(scan_policy='clamd-instream-text-v1'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,actor_id,request_id)
);
REVOKE ALL ON verivaro_private.evidence_objects FROM PUBLIC;
CREATE TRIGGER evidence_object_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.evidence_objects
 FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE TRIGGER evidence_no_truncate BEFORE TRUNCATE ON verivaro.evidence
 FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE FUNCTION verivaro_private.check_ingest_scope(t uuid,p uuid) RETURNS text[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $scope$
DECLARE ctx text[];a uuid;s uuid;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR t IS NULL OR p IS NULL THEN RAISE EXCEPTION 'ingestion denied' USING ERRCODE='42501'; END IF;
 ctx:=verivaro.bound_context();IF ctx IS NULL OR ctx[1]<>t::text THEN RAISE EXCEPTION 'ingestion denied' USING ERRCODE='42501';END IF;
 a:=ctx[2]::uuid;s:=ctx[3]::uuid;
 PERFORM verivaro_private.lock_identity(a);
 PERFORM 1 FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=a AND m.revoked_at IS NULL AND m.role IN ('owner','reviewer','contributor') FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ingestion denied' USING ERRCODE='42501';END IF;
 PERFORM 1 FROM verivaro.project_members m WHERE m.tenant_id=t AND m.project_id=p AND m.actor_id=a AND m.revoked_at IS NULL AND m.role IN ('owner','reviewer','contributor') AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp()) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ingestion denied' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) OR NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i WHERE i.actor_id=a AND i.session_id=s AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'ingestion denied' USING ERRCODE='42501';END IF;
 RETURN ctx;
END $scope$;
REVOKE ALL ON FUNCTION verivaro_private.check_ingest_scope(uuid,uuid) FROM PUBLIC;
CREATE FUNCTION verivaro_ingestion.authorize_upload(t uuid,p uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $auth$
BEGIN PERFORM verivaro_private.check_ingest_scope(t,p);RETURN true;END $auth$;
CREATE FUNCTION verivaro_ingestion.commit_upload(t uuid,p uuid,r uuid,e uuid,h text,n integer,k text,sealed bytea)
RETURNS TABLE(id uuid,sha256 text,bytes integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $commit$
DECLARE ctx text[];a uuid;s uuid;prior verivaro_private.evidence_objects%ROWTYPE;
BEGIN
 IF r IS NULL OR e IS NULL OR h IS NULL OR h!~'^[0-9a-f]{64}$' OR n IS NULL OR n NOT BETWEEN 1 AND 262144 OR k IS NULL OR k!~'^[a-z][a-z0-9_-]{0,31}$' OR sealed IS NULL OR octet_length(sealed)<>n+28 THEN RAISE EXCEPTION 'invalid ingestion' USING ERRCODE='22023';END IF;
 ctx:=verivaro_private.check_ingest_scope(t,p);a:=ctx[2]::uuid;s:=ctx[3]::uuid;
 SELECT * INTO prior FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.actor_id=a AND o.request_id=r;
 IF FOUND THEN
  IF prior.project_id<>p OR prior.sha256<>h OR prior.bytes<>n THEN RAISE EXCEPTION 'ingestion conflict' USING ERRCODE='23505';END IF;
  RETURN QUERY SELECT prior.evidence_id,prior.sha256,prior.bytes;RETURN;
 END IF;
 PERFORM pg_advisory_xact_lock(740129816153::bigint);
 IF (SELECT count(*) FROM verivaro_private.evidence_objects)>=4096 THEN RAISE EXCEPTION 'ingestion capacity exhausted' USING ERRCODE='54000';END IF;
 -- Recheck after the global capacity lock; permission changes are serialized
 -- by membership row locks and the actor lifecycle lock.
 PERFORM verivaro_private.check_ingest_scope(t,p);
 INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by) VALUES(e,t,p,h,'db-encrypted-v1',a);
 INSERT INTO verivaro_private.evidence_objects(evidence_id,tenant_id,project_id,actor_id,session_id,request_id,sha256,bytes,key_id,envelope,cipher_digest,scan_policy)
 VALUES(e,t,p,a,s,r,h,n,k,sealed,verivaro_private.digest(sealed,'sha256'),'clamd-instream-text-v1');
 RETURN QUERY SELECT e,h,n;
END $commit$;
REVOKE ALL ON FUNCTION verivaro_ingestion.authorize_upload(uuid,uuid),verivaro_ingestion.commit_upload(uuid,uuid,uuid,uuid,text,integer,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_ingestion.authorize_upload(uuid,uuid),verivaro_ingestion.commit_upload(uuid,uuid,uuid,uuid,text,integer,text,bytea) TO verivaro_evidence_ingestor;
COMMIT;
