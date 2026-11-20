BEGIN;
ALTER TABLE verivaro_private.evidence_objects DROP CONSTRAINT evidence_objects_media_type_check;
ALTER TABLE verivaro_private.evidence_objects ADD CONSTRAINT evidence_objects_media_type_check CHECK(media_type IN ('text/plain; charset=utf-8','image/png','application/pdf','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'));
CREATE OR REPLACE FUNCTION verivaro_ingestion.commit_upload_v2(t uuid,p uuid,r uuid,e uuid,h text,n integer,k text,sealed bytea,media text)
RETURNS TABLE(id uuid,sha256 text,bytes integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $commit$
DECLARE ctx text[];a uuid;s uuid;prior verivaro_private.evidence_objects%ROWTYPE;
BEGIN
 IF media IS NULL OR media NOT IN ('text/plain; charset=utf-8','image/png','application/pdf','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') OR r IS NULL OR e IS NULL OR h IS NULL OR h!~'^[0-9a-f]{64}$' OR n IS NULL OR n NOT BETWEEN 1 AND 262144 OR k IS NULL OR k!~'^[a-z][a-z0-9_-]{0,31}$' OR sealed IS NULL OR octet_length(sealed)<>n+28 THEN RAISE EXCEPTION 'invalid ingestion' USING ERRCODE='22023';END IF;
 ctx:=verivaro_private.check_ingest_scope(t,p);a:=ctx[2]::uuid;s:=ctx[3]::uuid;
 SELECT * INTO prior FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.actor_id=a AND o.request_id=r;
 IF FOUND THEN
  IF prior.project_id<>p OR prior.sha256<>h OR prior.bytes<>n OR prior.media_type<>media THEN RAISE EXCEPTION 'ingestion conflict' USING ERRCODE='23505';END IF;
  RETURN QUERY SELECT prior.evidence_id,prior.sha256,prior.bytes;RETURN;
 END IF;
 PERFORM pg_advisory_xact_lock(740129816153::bigint);
 IF (SELECT count(*) FROM verivaro_private.evidence_objects)>=4096 THEN RAISE EXCEPTION 'ingestion capacity exhausted' USING ERRCODE='54000';END IF;
 IF (SELECT count(*) FROM verivaro_private.evidence_objects WHERE tenant_id=t)>=256
 OR (SELECT COALESCE(sum(o.bytes),0) FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t)+n>33554432
 OR (SELECT COALESCE(sum(o.bytes),0) FROM verivaro_private.evidence_objects o WHERE o.tenant_id=t AND o.actor_id=a)+n>8388608
 THEN RAISE EXCEPTION 'evidence quota exhausted' USING ERRCODE='54000';END IF;
 -- Recheck after the global capacity lock; permission changes are serialized
 -- by membership row locks and the actor lifecycle lock.
 PERFORM verivaro_private.check_ingest_scope(t,p);
 INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by) VALUES(e,t,p,h,'db-encrypted-v1',a);
 INSERT INTO verivaro_private.evidence_objects(evidence_id,tenant_id,project_id,actor_id,session_id,request_id,sha256,bytes,key_id,envelope,cipher_digest,scan_policy,media_type)
 VALUES(e,t,p,a,s,r,h,n,k,sealed,verivaro_private.digest(sealed,'sha256'),'clamd-instream-format-v2',media);
 RETURN QUERY SELECT e,h,n;
END $commit$;

COMMIT;
