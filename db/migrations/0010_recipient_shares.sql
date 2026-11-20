-- G1: sensitive exports require a recipient-bound share and live identity.
BEGIN;
CREATE ROLE verivaro_recipient_gateway NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA verivaro_sharing TO verivaro_recipient_gateway;
ALTER TABLE verivaro_private.share_grants ADD COLUMN recipient_id uuid,
 ADD COLUMN recipient_generation uuid;
ALTER TABLE verivaro_private.share_grants ADD CONSTRAINT recipient_binding_shape
 CHECK ((recipient_id IS NULL)=(recipient_generation IS NULL));
CREATE FUNCTION verivaro_private.recipient_generation(a uuid) RETURNS uuid
LANGUAGE sql STABLE SET search_path=pg_catalog,verivaro_private AS $generation$
 SELECT COALESCE((SELECT generation FROM verivaro_private.actor_share_generations WHERE actor_id=a),
 '00000000-0000-0000-0000-000000000000'::uuid)
 WHERE a IS NOT NULL AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a)
$generation$;
REVOKE ALL ON FUNCTION verivaro_private.recipient_generation(uuid) FROM PUBLIC;

CREATE FUNCTION verivaro_sharing.issue_recipient_share(e uuid,s uuid,digest bytea,expiry timestamptz,recipient uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $issue$
DECLARE ctx text[]; item verivaro_private.released_exports%ROWTYPE; n timestamptz; generation uuid[]; rg uuid;
BEGIN
 ctx:=verivaro.bound_context();
 IF NOT verivaro.active_identity() THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO item FROM verivaro_private.released_exports WHERE export_id=e FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 n:=clock_timestamp();
 generation:=verivaro_private.share_owner_generation(item.tenant_id,item.project_id,ctx[2]::uuid);
 rg:=verivaro_private.recipient_generation(recipient);
 IF item.tenant_id::text<>ctx[1] OR item.revoked_at IS NOT NULL OR generation IS NULL OR rg IS NULL
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions WHERE actor_id=recipient AND revoked_at IS NULL AND expires_at>n)
 OR s IS NULL OR digest IS NULL OR octet_length(digest)<>32 OR expiry IS NULL
 OR expiry<=n OR expiry>n+interval '24 hours'
 THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 INSERT INTO verivaro_private.share_grants(share_id,export_id,issuer_id,token_digest,created_at,expires_at,owner_generation,recipient_id,recipient_generation)
 VALUES(s,e,ctx[2]::uuid,digest,n,expiry,generation,recipient,rg);
 INSERT INTO verivaro_private.share_events(export_id,share_id,action,actor_id) VALUES(e,s,'issued',ctx[2]::uuid);
END $issue$;

-- The dedicated gateway is a trusted verifier, not a public SQL interface.
-- It must derive actor/session/expiry exclusively from a verified recipient JWT.
CREATE FUNCTION verivaro_sharing.resolve_recipient_share(digest bytea,recipient uuid,sid uuid,token_expiry bigint)
RETURNS TABLE(artifact_id uuid,sha256 text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $resolve$
DECLARE grant_row verivaro_private.share_grants%ROWTYPE; item verivaro_private.released_exports%ROWTYPE; n timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR digest IS NULL OR octet_length(digest)<>32
 OR recipient IS NULL OR sid IS NULL OR token_expiry IS NULL THEN RETURN; END IF;
 SELECT g.* INTO grant_row FROM verivaro_private.share_grants g WHERE g.token_digest=digest AND g.recipient_id=recipient;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT e.* INTO item FROM verivaro_private.released_exports e WHERE e.export_id=grant_row.export_id FOR SHARE;
 IF NOT FOUND OR item.revoked_at IS NOT NULL THEN RETURN; END IF;
 SELECT g.* INTO grant_row FROM verivaro_private.share_grants g WHERE g.share_id=grant_row.share_id FOR SHARE;
 n:=clock_timestamp();
 IF NOT FOUND OR grant_row.recipient_id IS DISTINCT FROM recipient OR grant_row.revoked_at IS NOT NULL OR grant_row.expires_at<=n
 OR grant_row.owner_generation IS NULL
 OR grant_row.owner_generation IS DISTINCT FROM verivaro_private.share_owner_generation(item.tenant_id,item.project_id,grant_row.issuer_id)
 OR grant_row.recipient_generation IS DISTINCT FROM verivaro_private.recipient_generation(recipient)
 OR token_expiry<=floor(extract(epoch FROM n)) OR token_expiry>floor(extract(epoch FROM n))+3600
 OR NOT EXISTS(SELECT 1 FROM verivaro_private.identity_sessions i
 WHERE i.actor_id=recipient AND i.session_id=sid AND i.revoked_at IS NULL AND i.expires_at>n
 AND extract(epoch FROM i.expires_at)>=token_expiry)
 THEN RETURN; END IF;
 INSERT INTO verivaro_private.share_events(export_id,share_id,action,actor_id) VALUES(item.export_id,grant_row.share_id,'accessed',recipient);
 RETURN QUERY SELECT item.artifact_id,item.sha256;
END $resolve$;
CREATE OR REPLACE FUNCTION verivaro_sharing.resolve_share(digest bytea)
RETURNS TABLE(artifact_id uuid,sha256 text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $resolve$
DECLARE grant_row verivaro_private.share_grants%ROWTYPE; item verivaro_private.released_exports%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR digest IS NULL OR octet_length(digest)<>32 THEN RETURN; END IF;
 SELECT g.* INTO grant_row FROM verivaro_private.share_grants g WHERE g.token_digest=digest;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT e.* INTO item FROM verivaro_private.released_exports e WHERE e.export_id=grant_row.export_id FOR SHARE;
 IF NOT FOUND OR item.revoked_at IS NOT NULL OR NOT item.bearer_allowed THEN RETURN; END IF;
 SELECT g.* INTO grant_row FROM verivaro_private.share_grants g WHERE g.share_id=grant_row.share_id FOR SHARE;
 IF NOT FOUND OR grant_row.revoked_at IS NOT NULL OR grant_row.expires_at<=clock_timestamp()
 OR grant_row.recipient_id IS NOT NULL
 OR grant_row.owner_generation IS DISTINCT FROM verivaro_private.share_owner_generation(item.tenant_id,item.project_id,grant_row.issuer_id) OR grant_row.owner_generation IS NULL THEN RETURN; END IF;
 INSERT INTO verivaro_private.share_events(export_id,share_id,action) VALUES(item.export_id,grant_row.share_id,'accessed');
 RETURN QUERY SELECT item.artifact_id,item.sha256;
END $resolve$;


REVOKE ALL ON FUNCTION verivaro_sharing.issue_recipient_share(uuid,uuid,bytea,timestamptz,uuid),verivaro_sharing.resolve_recipient_share(bytea,uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_sharing.issue_recipient_share(uuid,uuid,bytea,timestamptz,uuid) TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION verivaro_sharing.resolve_recipient_share(bytea,uuid,uuid,bigint) TO verivaro_recipient_gateway;
COMMIT;
