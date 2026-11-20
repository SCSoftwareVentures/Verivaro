-- G1: exact-export, expiring external sharing with no general project access.
BEGIN;
CREATE ROLE verivaro_share_gateway NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE verivaro_release_service NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA verivaro_sharing;
REVOKE ALL ON SCHEMA verivaro_sharing FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_sharing TO verivaro_runtime,verivaro_share_gateway,verivaro_release_service;
CREATE TABLE verivaro_private.released_exports(
 export_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL,
 artifact_id uuid NOT NULL UNIQUE,
 sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 bearer_allowed boolean NOT NULL DEFAULT false,
 revoked_at timestamptz,
 FOREIGN KEY(tenant_id,project_id) REFERENCES verivaro.projects(tenant_id,id)
);
CREATE TABLE verivaro_private.share_grants(
 share_id uuid PRIMARY KEY, export_id uuid NOT NULL REFERENCES verivaro_private.released_exports(export_id),
 issuer_id uuid NOT NULL, token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32),
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours')
);
CREATE INDEX share_grants_export_idx ON verivaro_private.share_grants(export_id);
CREATE TABLE verivaro_private.share_events(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 export_id uuid NOT NULL REFERENCES verivaro_private.released_exports(export_id),
 share_id uuid REFERENCES verivaro_private.share_grants(share_id),
 action text NOT NULL CHECK(action IN ('issued','revoked','accessed','export_revoked')),
 actor_id uuid, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON verivaro_private.released_exports,verivaro_private.share_grants,verivaro_private.share_events FROM PUBLIC;
CREATE TRIGGER share_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.share_events FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();

-- Only the separately trusted release worker may register an approved export.
-- This is not itself an approval workflow or proof of storage integrity.
CREATE FUNCTION verivaro_sharing.register_export(e uuid,t uuid,p uuid,artifact uuid,hash text,allow_bearer boolean DEFAULT false) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $register$
 INSERT INTO verivaro_private.released_exports(export_id,tenant_id,project_id,artifact_id,sha256,bearer_allowed)
 VALUES(e,t,p,artifact,hash,allow_bearer)
$register$;
CREATE FUNCTION verivaro_sharing.revoke_export(e uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $revoke_export$
BEGIN
 UPDATE verivaro_private.released_exports SET revoked_at=clock_timestamp() WHERE export_id=e AND revoked_at IS NULL;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO verivaro_private.share_events(export_id,action) VALUES(e,'export_revoked');
 RETURN true;
END $revoke_export$;

-- Explicit authorization even when SECURITY DEFINER bypasses table RLS.
-- Conservative launch policy: tenant owner AND active project owner only.
CREATE FUNCTION verivaro_private.share_owner(t uuid,p uuid,a uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,verivaro_private AS $owner$
 SELECT EXISTS(SELECT 1 FROM verivaro.memberships m
 JOIN verivaro.project_members pm ON pm.tenant_id=m.tenant_id AND pm.actor_id=m.actor_id
 WHERE m.tenant_id=t AND pm.project_id=p AND m.actor_id=a
 AND m.role='owner' AND pm.role='owner' AND m.revoked_at IS NULL AND pm.revoked_at IS NULL
 AND (pm.expires_at IS NULL OR pm.expires_at>statement_timestamp())
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=a))
$owner$;
REVOKE ALL ON FUNCTION verivaro_private.share_owner(uuid,uuid,uuid) FROM PUBLIC;

CREATE FUNCTION verivaro_sharing.issue_share(e uuid,s uuid,digest bytea,expiry timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $issue$
DECLARE ctx text[]; item verivaro_private.released_exports%ROWTYPE; n timestamptz;
BEGIN
 ctx:=verivaro.bound_context();
 IF NOT verivaro.active_identity() THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO item FROM verivaro_private.released_exports WHERE export_id=e FOR SHARE;
 n:=clock_timestamp();
 IF NOT FOUND OR item.tenant_id::text<>ctx[1] OR item.revoked_at IS NOT NULL OR NOT item.bearer_allowed
 OR NOT verivaro_private.share_owner(item.tenant_id,item.project_id,ctx[2]::uuid)
 OR s IS NULL OR digest IS NULL OR octet_length(digest)<>32 OR expiry IS NULL
 OR expiry<=n OR expiry>n+interval '24 hours'
 THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 INSERT INTO verivaro_private.share_grants(share_id,export_id,issuer_id,token_digest,created_at,expires_at)
 VALUES(s,e,ctx[2]::uuid,digest,n,expiry);
 INSERT INTO verivaro_private.share_events(export_id,share_id,action,actor_id) VALUES(e,s,'issued',ctx[2]::uuid);
END $issue$;

CREATE FUNCTION verivaro_sharing.revoke_share(s uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $revoke_share$
DECLARE ctx text[]; item verivaro_private.released_exports%ROWTYPE;
BEGIN
 ctx:=verivaro.bound_context();
 IF NOT verivaro.active_identity() THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 SELECT e.* INTO item FROM verivaro_private.released_exports e JOIN verivaro_private.share_grants g ON g.export_id=e.export_id WHERE g.share_id=s;
 IF NOT FOUND OR item.tenant_id::text<>ctx[1] OR NOT verivaro_private.share_owner(item.tenant_id,item.project_id,ctx[2]::uuid)
 THEN RAISE EXCEPTION 'share denied' USING ERRCODE='42501'; END IF;
 UPDATE verivaro_private.share_grants SET revoked_at=clock_timestamp() WHERE share_id=s AND revoked_at IS NULL;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO verivaro_private.share_events(export_id,share_id,action,actor_id) VALUES(item.export_id,s,'revoked',ctx[2]::uuid);
 RETURN true;
END $revoke_share$;

-- Only the private gateway may resolve a digest. The result is an internal
-- artifact handle, not a public URL, and never grants access to a project.
CREATE FUNCTION verivaro_sharing.resolve_share(digest bytea)
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
 OR NOT verivaro_private.share_owner(item.tenant_id,item.project_id,grant_row.issuer_id) THEN RETURN; END IF;
 INSERT INTO verivaro_private.share_events(export_id,share_id,action) VALUES(item.export_id,grant_row.share_id,'accessed');
 RETURN QUERY SELECT item.artifact_id,item.sha256;
END $resolve$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA verivaro_sharing FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_sharing.register_export(uuid,uuid,uuid,uuid,text,boolean),verivaro_sharing.revoke_export(uuid) TO verivaro_release_service;
GRANT EXECUTE ON FUNCTION verivaro_sharing.issue_share(uuid,uuid,bytea,timestamptz),verivaro_sharing.revoke_share(uuid) TO verivaro_runtime;
GRANT EXECUTE ON FUNCTION verivaro_sharing.resolve_share(bytea) TO verivaro_share_gateway;
COMMIT;
