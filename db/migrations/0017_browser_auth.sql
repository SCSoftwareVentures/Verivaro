BEGIN;
CREATE TABLE verivaro_private.browser_flows(
 state_hash bytea PRIMARY KEY CHECK(octet_length(state_hash)=32),
 cookie_hash bytea NOT NULL CHECK(octet_length(cookie_hash)=32),
 envelope bytea NOT NULL CHECK(octet_length(envelope) BETWEEN 32 AND 2048),
 expires_at timestamptz NOT NULL
);
CREATE INDEX browser_flow_expiry ON verivaro_private.browser_flows(expires_at);
CREATE TABLE verivaro_private.browser_sessions(
 handle_hash bytea PRIMARY KEY CHECK(octet_length(handle_hash)=32),
 session_id uuid UNIQUE NOT NULL REFERENCES verivaro_private.identity_sessions(session_id),
 envelope bytea NOT NULL CHECK(octet_length(envelope) BETWEEN 32 AND 8192),
 expires_at timestamptz NOT NULL
);
CREATE INDEX browser_session_expiry ON verivaro_private.browser_sessions(expires_at);
REVOKE ALL ON verivaro_private.browser_flows,verivaro_private.browser_sessions FROM PUBLIC;
CREATE FUNCTION verivaro_identity.store_browser_flow(s bytea,c bytea,e bytea) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $flow$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR s IS NULL OR octet_length(s)<>32 OR c IS NULL OR octet_length(c)<>32 OR e IS NULL OR octet_length(e) NOT BETWEEN 32 AND 2048 THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(740129816150::bigint);
 DELETE FROM verivaro_private.browser_flows WHERE expires_at<=clock_timestamp();
 IF (SELECT count(*) FROM verivaro_private.browser_flows)>=4096 THEN RETURN false; END IF;
 INSERT INTO verivaro_private.browser_flows VALUES(s,c,e,clock_timestamp()+interval '5 minutes');
 RETURN true;
END $flow$;
CREATE FUNCTION verivaro_identity.take_browser_flow(s bytea,c bytea) RETURNS bytea
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $take$
 DELETE FROM verivaro_private.browser_flows WHERE state_hash=s AND cookie_hash=c AND expires_at>clock_timestamp() RETURNING envelope
$take$;
CREATE FUNCTION verivaro_identity.store_browser_session(h bytea,s uuid,e bytea) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $store$
DECLARE expiry timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR h IS NULL OR octet_length(h)<>32 OR e IS NULL OR octet_length(e) NOT BETWEEN 32 AND 8192 THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(740129816151::bigint);
 DELETE FROM verivaro_private.browser_sessions WHERE expires_at<=clock_timestamp();
 IF (SELECT count(*) FROM verivaro_private.browser_sessions)>=10000 THEN RETURN false; END IF;
 SELECT i.expires_at INTO expiry FROM verivaro_private.identity_sessions i WHERE i.session_id=s AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=i.actor_id) FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO verivaro_private.browser_sessions VALUES(h,s,e,expiry);
 RETURN true;
END $store$;
CREATE FUNCTION verivaro_identity.read_browser_session(h bytea) RETURNS bytea
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $read$
 SELECT b.envelope FROM verivaro_private.browser_sessions b JOIN verivaro_private.identity_sessions i USING(session_id)
 WHERE b.handle_hash=h AND b.expires_at>statement_timestamp() AND i.expires_at>statement_timestamp() AND i.revoked_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors d WHERE d.actor_id=i.actor_id)
$read$;
CREATE FUNCTION verivaro_identity.logout_browser(h bytea) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $logout$
DECLARE s uuid; a uuid;
BEGIN
 DELETE FROM verivaro_private.browser_sessions WHERE handle_hash=h RETURNING session_id INTO s;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT actor_id INTO a FROM verivaro_private.identity_sessions WHERE session_id=s;
 PERFORM verivaro_identity.revoke_session(a,s);
 RETURN true;
END $logout$;
REVOKE ALL ON FUNCTION verivaro_identity.store_browser_flow(bytea,bytea,bytea),verivaro_identity.take_browser_flow(bytea,bytea),verivaro_identity.store_browser_session(bytea,uuid,bytea),verivaro_identity.read_browser_session(bytea),verivaro_identity.logout_browser(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_identity.store_browser_flow(bytea,bytea,bytea),verivaro_identity.take_browser_flow(bytea,bytea),verivaro_identity.store_browser_session(bytea,uuid,bytea),verivaro_identity.read_browser_session(bytea),verivaro_identity.logout_browser(bytea) TO verivaro_identity_service;
COMMIT;
