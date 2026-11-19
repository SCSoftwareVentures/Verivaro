BEGIN;
CREATE ROLE verivaro_evidence_reader NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA verivaro_ingestion TO verivaro_evidence_reader;
CREATE TABLE verivaro_private.evidence_access_events(
 event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 evidence_id uuid NOT NULL REFERENCES verivaro_private.evidence_objects(evidence_id),
 tenant_id uuid NOT NULL,project_id uuid NOT NULL,actor_id uuid NOT NULL,session_id uuid NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.evidence_access_events FROM PUBLIC;
CREATE TRIGGER evidence_access_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON verivaro_private.evidence_access_events
 FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();
CREATE FUNCTION verivaro_ingestion.fetch_object(t uuid,p uuid,e uuid)
RETURNS TABLE(id uuid,sha256 text,bytes integer,key_id text,media_type text,envelope bytea,cipher_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $fetch$
DECLARE ctx text[];a uuid;s uuid;obj verivaro_private.evidence_objects%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR t IS NULL OR p IS NULL OR e IS NULL THEN RAISE EXCEPTION 'evidence access denied' USING ERRCODE='42501'; END IF;
 ctx:=verivaro.bound_context();IF ctx IS NULL OR ctx[1]<>t::text THEN RAISE EXCEPTION 'evidence access denied' USING ERRCODE='42501';END IF;
 a:=ctx[2]::uuid;s:=ctx[3]::uuid;
 PERFORM verivaro_private.lock_identity(a);
 PERFORM 1 FROM verivaro.memberships m WHERE m.tenant_id=t AND m.actor_id=a AND m.revoked_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'evidence access denied' USING ERRCODE='42501';END IF;
 PERFORM 1 FROM verivaro.project_members m WHERE m.tenant_id=t AND m.project_id=p AND m.actor_id=a AND m.revoked_at IS NULL AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp()) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'evidence access denied' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a) OR NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i WHERE i.actor_id=a AND i.session_id=s AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp()) THEN RAISE EXCEPTION 'evidence access denied' USING ERRCODE='42501';END IF;
 SELECT o.* INTO obj FROM verivaro_private.evidence_objects o JOIN verivaro.evidence v ON v.id=o.evidence_id AND v.tenant_id=o.tenant_id AND v.project_id=o.project_id AND v.sha256=o.sha256
 WHERE o.evidence_id=e AND o.tenant_id=t AND o.project_id=p AND v.storage_ref='db-encrypted-v1';
 IF NOT FOUND THEN RAISE EXCEPTION 'evidence access denied' USING ERRCODE='42501';END IF;
 -- This event records authorized ciphertext access, not delivered plaintext.
 INSERT INTO verivaro_private.evidence_access_events(evidence_id,tenant_id,project_id,actor_id,session_id) VALUES(e,t,p,a,s);
 RETURN QUERY SELECT obj.evidence_id,obj.sha256,obj.bytes,obj.key_id,obj.media_type,obj.envelope,encode(obj.cipher_digest,'hex');
END $fetch$;
REVOKE ALL ON FUNCTION verivaro_ingestion.fetch_object(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_ingestion.fetch_object(uuid,uuid,uuid) TO verivaro_evidence_reader;
COMMIT;
