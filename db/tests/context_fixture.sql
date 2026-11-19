-- CI ONLY: ephemeral random key and privileged signer. Never apply in production.
INSERT INTO verivaro_private.context_key(key_bytes) VALUES (verivaro_private.gen_random_bytes(32));
CREATE FUNCTION verivaro_private.ci_sign(t uuid, a uuid, pid integer, xid text, lifetime integer DEFAULT 45)
RETURNS text LANGUAGE sql VOLATILE SET search_path = pg_catalog, verivaro_private AS $$
 SELECT payload || '|' || encode(verivaro_private.hmac(convert_to(payload,'UTF8'),key_bytes,'sha256'),'hex')
 FROM verivaro_private.context_key CROSS JOIN LATERAL (
  SELECT concat_ws('|','v1',t::text,a::text,pid::text,xid,
    (floor(extract(epoch FROM clock_timestamp()))::bigint+lifetime)::text) AS payload
 ) s WHERE singleton
$$;
REVOKE ALL ON FUNCTION verivaro_private.ci_sign(uuid,uuid,integer,text,integer) FROM PUBLIC;
