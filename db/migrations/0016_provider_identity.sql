BEGIN;
CREATE ROLE verivaro_identity_provisioner NOLOGIN NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA verivaro_identity TO verivaro_identity_provisioner;
-- Explicit provisioning only. No email matching, auto-enrollment or rebinding.
CREATE TABLE verivaro_private.provider_bindings(
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 512),
 subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
 actor_id uuid NOT NULL UNIQUE,
 provision_ref uuid NOT NULL UNIQUE,
 provisioned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 disabled_at timestamptz,
 disable_ref uuid UNIQUE,
 PRIMARY KEY(issuer,subject_digest),
 CHECK((disabled_at IS NULL)=(disable_ref IS NULL))
);
REVOKE ALL ON verivaro_private.provider_bindings FROM PUBLIC;
CREATE FUNCTION verivaro_identity.provision_binding(iss text,subject_hash bytea,a uuid,ref uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $provision$
BEGIN
 PERFORM verivaro_private.lock_identity(a);
 IF iss IS NULL OR octet_length(iss) NOT BETWEEN 1 AND 512 OR subject_hash IS NULL OR octet_length(subject_hash)<>32 OR ref IS NULL
 OR EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id=a)
 OR NOT (EXISTS(SELECT 1 FROM verivaro.memberships WHERE actor_id=a) OR EXISTS(SELECT 1 FROM verivaro_private.identity_sessions WHERE actor_id=a))
 THEN RAISE EXCEPTION 'identity provisioning denied' USING ERRCODE='42501'; END IF;
 INSERT INTO verivaro_private.provider_bindings(issuer,subject_digest,actor_id,provision_ref) VALUES(iss,subject_hash,a,ref);
END $provision$;
CREATE FUNCTION verivaro_identity.disable_binding(iss text,subject_hash bytea,ref uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $disable$
DECLARE a uuid;
BEGIN
 IF ref IS NULL THEN RETURN false; END IF;
 SELECT actor_id INTO a FROM verivaro_private.provider_bindings WHERE issuer=iss AND subject_digest=subject_hash AND disabled_at IS NULL FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM verivaro_identity.disable_actor(a);
 UPDATE verivaro_private.provider_bindings SET disabled_at=clock_timestamp(),disable_ref=ref WHERE issuer=iss AND subject_digest=subject_hash;
 RETURN true;
END $disable$;
CREATE TABLE verivaro_private.login_challenges(
 nonce_digest bytea PRIMARY KEY CHECK(octet_length(nonce_digest)=32),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 512),
 audience text NOT NULL CHECK(octet_length(audience) BETWEEN 1 AND 256),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 CHECK(expires_at>created_at)
);
REVOKE ALL ON verivaro_private.login_challenges FROM PUBLIC;
CREATE INDEX login_challenge_expiry ON verivaro_private.login_challenges(expires_at);
CREATE FUNCTION verivaro_identity.begin_login(nonce_hash bytea,binding_hash bytea,iss text,aud text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $begin$
DECLARE n timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR nonce_hash IS NULL OR octet_length(nonce_hash)<>32
 OR binding_hash IS NULL OR octet_length(binding_hash)<>32 OR iss IS NULL OR octet_length(iss) NOT BETWEEN 1 AND 512 OR aud IS NULL OR octet_length(aud) NOT BETWEEN 1 AND 256 THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock(740129816149::bigint);
 n:=clock_timestamp();
 DELETE FROM verivaro_private.login_challenges WHERE expires_at<=n;
 IF (SELECT count(*) FROM verivaro_private.login_challenges)>=4096 OR
 (SELECT count(*) FROM verivaro_private.login_challenges WHERE created_at>n-interval '1 minute')>=120 THEN RETURN false; END IF;
 INSERT INTO verivaro_private.login_challenges(nonce_digest,binding_digest,issuer,audience,created_at,expires_at)
 VALUES(nonce_hash,binding_hash,iss,aud,n,n+interval '5 minutes');
 RETURN true;
END $begin$;
CREATE FUNCTION verivaro_identity.redeem_login(nonce_hash bytea,binding_hash bytea,iss text,aud text,subject_hash bytea,s uuid,auth_at timestamptz,expiry timestamptz) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,verivaro_private AS $redeem$
DECLARE c verivaro_private.login_challenges%ROWTYPE; a uuid; n timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR nonce_hash IS NULL OR octet_length(nonce_hash)<>32
 OR binding_hash IS NULL OR octet_length(binding_hash)<>32 OR subject_hash IS NULL OR octet_length(subject_hash)<>32
 OR iss IS NULL OR aud IS NULL OR s IS NULL OR auth_at IS NULL OR expiry IS NULL THEN RAISE EXCEPTION 'login denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO c FROM verivaro_private.login_challenges WHERE nonce_digest=nonce_hash FOR UPDATE;
 n:=clock_timestamp();
 IF NOT FOUND OR c.binding_digest<>binding_hash OR c.issuer<>iss OR c.audience<>aud OR c.consumed_at IS NOT NULL OR c.expires_at<=n
 OR auth_at<c.created_at-interval '1 second' OR auth_at>n OR expiry<=n OR expiry>n+interval '15 minutes'
 THEN RAISE EXCEPTION 'login denied' USING ERRCODE='42501'; END IF;
 SELECT actor_id INTO a FROM verivaro_private.provider_bindings WHERE issuer=iss AND subject_digest=subject_hash AND disabled_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'login denied' USING ERRCODE='42501'; END IF;
 PERFORM verivaro_identity.register_session(a,s,auth_at,expiry);
 UPDATE verivaro_private.login_challenges SET consumed_at=clock_timestamp() WHERE nonce_digest=nonce_hash;
 RETURN a;
END $redeem$;
REVOKE ALL ON FUNCTION verivaro_identity.provision_binding(text,bytea,uuid,uuid),verivaro_identity.disable_binding(text,bytea,uuid),verivaro_identity.begin_login(bytea,bytea,text,text),verivaro_identity.redeem_login(bytea,bytea,text,text,bytea,uuid,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verivaro_identity.provision_binding(text,bytea,uuid,uuid),verivaro_identity.disable_binding(text,bytea,uuid) TO verivaro_identity_provisioner;
GRANT EXECUTE ON FUNCTION verivaro_identity.begin_login(bytea,bytea,text,text),verivaro_identity.redeem_login(bytea,bytea,text,text,bytea,uuid,timestamptz,timestamptz) TO verivaro_identity_service;
-- No alternate direct registration path for the gateway credential.
REVOKE EXECUTE ON FUNCTION verivaro_identity.register_session(uuid,uuid,timestamptz,timestamptz) FROM verivaro_identity_service;
COMMIT;
