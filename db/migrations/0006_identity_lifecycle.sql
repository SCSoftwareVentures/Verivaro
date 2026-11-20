-- G1: trusted identity lifecycle and audited, fail-closed recovery.
BEGIN;
CREATE ROLE verivaro_identity_service NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE verivaro_recovery_service NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA verivaro_identity;
REVOKE ALL ON SCHEMA verivaro_identity FROM PUBLIC;
GRANT USAGE ON SCHEMA verivaro_identity TO verivaro_identity_service,verivaro_recovery_service;

CREATE TABLE verivaro_private.identity_fences(
 actor_id uuid PRIMARY KEY,
 authenticated_after timestamptz NOT NULL
);
CREATE TABLE verivaro_private.identity_events(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 actor_id uuid NOT NULL,
 session_id uuid,
 kind text NOT NULL CHECK(kind IN ('session_registered','session_revoked','actor_disabled','actor_recovered')),
 authorization_ref uuid UNIQUE,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((kind='actor_recovered')=(authorization_ref IS NOT NULL))
);
REVOKE ALL ON verivaro_private.identity_fences,verivaro_private.identity_events FROM PUBLIC;
CREATE FUNCTION verivaro_private.identity_event_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $evt$
BEGIN
 RAISE EXCEPTION 'identity event history is append-only' USING ERRCODE='42501';
END $evt$;
REVOKE ALL ON FUNCTION verivaro_private.identity_event_immutable() FROM PUBLIC;
CREATE TRIGGER identity_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
 ON verivaro_private.identity_events FOR EACH STATEMENT EXECUTE FUNCTION verivaro_private.identity_event_immutable();

-- Every lifecycle transition for an actor is serialized. Direct privileged DML
-- is outside the service contract and must not be used for ordinary operations.
CREATE FUNCTION verivaro_private.lock_identity(a uuid) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $lock$
BEGIN
 IF a IS NULL OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'identity transition denied' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(a::text,724681));
END $lock$;
REVOKE ALL ON FUNCTION verivaro_private.lock_identity(uuid) FROM PUBLIC;

CREATE FUNCTION verivaro_identity.register_session(a uuid,s uuid,authenticated_at timestamptz,expiry timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $reg$
DECLARE n timestamptz;
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 n:=clock_timestamp();
 IF s IS NULL OR authenticated_at IS NULL OR expiry IS NULL
 OR authenticated_at>n OR authenticated_at<n-interval '5 minutes'
 OR expiry<=n OR expiry>n+interval '1 hour'
 OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=a)
 OR EXISTS(SELECT 1 FROM verivaro_private.identity_fences f WHERE f.actor_id=a AND authenticated_at<=f.authenticated_after)
 THEN RAISE EXCEPTION 'session registration denied' USING ERRCODE='42501'; END IF;
 INSERT INTO verivaro_private.identity_sessions(session_id,actor_id,created_at,expires_at) VALUES(s,a,n,expiry);
 INSERT INTO verivaro_private.identity_events(actor_id,session_id,kind) VALUES(a,s,'session_registered');
END $reg$;

CREATE FUNCTION verivaro_identity.revoke_session(a uuid,s uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $rev$
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 UPDATE verivaro_private.identity_sessions SET revoked_at=clock_timestamp()
 WHERE actor_id=a AND session_id=s AND revoked_at IS NULL;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO verivaro_private.identity_events(actor_id,session_id,kind) VALUES(a,s,'session_revoked');
 RETURN true;
END $rev$;

CREATE FUNCTION verivaro_identity.disable_actor(a uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $disable$
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 INSERT INTO verivaro_private.disabled_actors(actor_id) VALUES(a) ON CONFLICT DO NOTHING;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE verivaro_private.identity_sessions SET revoked_at=clock_timestamp() WHERE actor_id=a AND revoked_at IS NULL;
 INSERT INTO verivaro_private.identity_events(actor_id,kind) VALUES(a,'actor_disabled');
 RETURN true;
END $disable$;

-- Only a separately credentialed recovery operator may call this after
-- independently approved reauthentication. The authorization UUID is a
-- correlation/replay identifier, not a cryptographic proof of approval.
CREATE FUNCTION verivaro_identity.recover_actor(a uuid,approval uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $recover$
DECLARE n timestamptz;
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 IF approval IS NULL OR NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a)
 THEN RAISE EXCEPTION 'recovery denied' USING ERRCODE='42501'; END IF;
 n:=clock_timestamp();
 -- All old sessions, including sessions not revoked by an emergency admin
 -- disable, are permanently invalidated before removal of the disable fence.
 UPDATE verivaro_private.identity_sessions SET revoked_at=n WHERE actor_id=a AND revoked_at IS NULL;
 INSERT INTO verivaro_private.identity_fences(actor_id,authenticated_after) VALUES(a,n)
 ON CONFLICT(actor_id) DO UPDATE SET authenticated_after=GREATEST(verivaro_private.identity_fences.authenticated_after,EXCLUDED.authenticated_after);
 INSERT INTO verivaro_private.identity_events(actor_id,kind,authorization_ref) VALUES(a,'actor_recovered',approval);
 DELETE FROM verivaro_private.disabled_actors WHERE actor_id=a;
END $recover$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA verivaro_identity FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_identity.register_session(uuid,uuid,timestamptz,timestamptz),
 verivaro_identity.revoke_session(uuid,uuid) TO verivaro_identity_service;
GRANT EXECUTE ON FUNCTION verivaro_identity.disable_actor(uuid),verivaro_identity.recover_actor(uuid,uuid) TO verivaro_recovery_service;
COMMIT;
