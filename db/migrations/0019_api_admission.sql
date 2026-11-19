BEGIN;
CREATE ROLE verivaro_api_admission NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA verivaro_admission TO verivaro_api_admission;
CREATE TABLE verivaro_private.api_rate_state(
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 bucket bigint NOT NULL DEFAULT -1, requests integer NOT NULL DEFAULT 0 CHECK(requests>=0),
 global_limit integer NOT NULL DEFAULT 600 CHECK(global_limit BETWEEN 1 AND 10000),
 peer_limit integer NOT NULL DEFAULT 120 CHECK(peer_limit BETWEEN 1 AND global_limit),
 actor_limit integer NOT NULL DEFAULT 60 CHECK(actor_limit BETWEEN 1 AND global_limit)
);
INSERT INTO verivaro_private.api_rate_state DEFAULT VALUES;
CREATE TABLE verivaro_private.api_rate_keys(
 kind text NOT NULL CHECK(kind IN ('peer','actor')),
 key_digest bytea NOT NULL CHECK(octet_length(key_digest)=32),
 requests integer NOT NULL CHECK(requests>=1),
 PRIMARY KEY(kind,key_digest)
);
REVOKE ALL ON verivaro_private.api_rate_state,verivaro_private.api_rate_keys FROM PUBLIC;
CREATE FUNCTION verivaro_private.api_rate(k text,d bytea) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $rate$
DECLARE cfg verivaro_private.api_rate_state%ROWTYPE; b bigint; n integer; cap integer;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR k NOT IN ('peer','actor') OR d IS NULL OR octet_length(d)<>32 THEN RETURN false; END IF;
 SELECT * INTO cfg FROM verivaro_private.api_rate_state WHERE singleton FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 b:=floor(extract(epoch FROM clock_timestamp())/60)::bigint;
 IF b>cfg.bucket THEN
  DELETE FROM verivaro_private.api_rate_keys;
  UPDATE verivaro_private.api_rate_state SET bucket=b,requests=0 WHERE singleton;
  cfg.requests:=0;
 END IF;
 -- Charge global capacity before authentication, including denied peers.
 IF k='peer' THEN
  IF cfg.requests>=cfg.global_limit THEN RETURN false; END IF;
  UPDATE verivaro_private.api_rate_state SET requests=requests+1 WHERE singleton;
  cap:=cfg.peer_limit;
 ELSE cap:=cfg.actor_limit; END IF;
 SELECT requests INTO n FROM verivaro_private.api_rate_keys WHERE kind=k AND key_digest=d;
 IF COALESCE(n,0)>=cap THEN RETURN false; END IF;
 -- A compromised trusted caller cannot create unbounded distinct actor rows.
 IF n IS NULL AND (SELECT count(*) FROM verivaro_private.api_rate_keys WHERE kind=k)>=cfg.global_limit THEN RETURN false; END IF;
 INSERT INTO verivaro_private.api_rate_keys(kind,key_digest,requests) VALUES(k,d,1)
 ON CONFLICT(kind,key_digest) DO UPDATE SET requests=api_rate_keys.requests+1;
 RETURN true;
END $rate$;
REVOKE ALL ON FUNCTION verivaro_private.api_rate(text,bytea) FROM PUBLIC;
CREATE FUNCTION verivaro_admission.api_peer(d bytea) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $peer$
 SELECT verivaro_private.api_rate('peer',d)
$peer$;
CREATE FUNCTION verivaro_admission.api_actor(d bytea) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $actor$
 SELECT verivaro_private.api_rate('actor',d)
$actor$;
REVOKE ALL ON FUNCTION verivaro_admission.api_peer(bytea),verivaro_admission.api_actor(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_admission.api_peer(bytea),verivaro_admission.api_actor(bytea) TO verivaro_api_admission;
COMMIT;
