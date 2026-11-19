-- G1 lifecycle acceptance on synthetic data only.
-- Separate roles: neither runtime nor identity issuance service can restore an account.
DO $acl$
BEGIN
 IF has_schema_privilege('verivaro_runtime','verivaro_identity','USAGE')
 OR has_function_privilege('verivaro_runtime','verivaro_identity.register_session(uuid,uuid,timestamptz,timestamptz)','EXECUTE')
 OR has_function_privilege('verivaro_identity_service','verivaro_identity.recover_actor(uuid,uuid)','EXECUTE')
 OR has_function_privilege('verivaro_recovery_service','verivaro_identity.register_session(uuid,uuid,timestamptz,timestamptz)','EXECUTE')
 OR has_schema_privilege('verivaro_identity_service','verivaro_private','USAGE')
 OR has_schema_privilege('verivaro_recovery_service','verivaro_private','USAGE')
 OR has_table_privilege('verivaro_identity_service','verivaro_private.identity_sessions','UPDATE')
 OR has_table_privilege('verivaro_recovery_service','verivaro_private.identity_events','DELETE')
 THEN RAISE EXCEPTION 'lifecycle privilege boundary broken'; END IF;
END $acl$;

SET ROLE verivaro_identity_service;
SELECT verivaro_identity.register_session('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abd',clock_timestamp()-interval '1 second',clock_timestamp()+interval '20 minutes');
SELECT verivaro_identity.register_session('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abe',clock_timestamp()-interval '1 second',clock_timestamp()+interval '20 minutes');
DO $revoke$
BEGIN
 IF verivaro_identity.revoke_session('22345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abd')
 THEN RAISE EXCEPTION 'cross-actor revocation'; END IF;
 IF NOT verivaro_identity.revoke_session('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abd')
 THEN RAISE EXCEPTION 'revocation failed'; END IF;
 IF verivaro_identity.revoke_session('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abd')
 THEN RAISE EXCEPTION 'revocation not idempotent'; END IF;
END $revoke$;
RESET ROLE;
DO $verify$
BEGIN
 IF (SELECT count(*) FROM verivaro_private.identity_sessions WHERE actor_id='12345678-1234-4234-8234-123456789abc' AND revoked_at IS NULL)<>1
 THEN RAISE EXCEPTION 'session-specific revocation failed'; END IF;
END $verify$;

SET ROLE verivaro_recovery_service;
SELECT verivaro_identity.disable_actor('12345678-1234-4234-8234-123456789abc');
RESET ROLE;
SET ROLE verivaro_identity_service;
DO $disabled$
BEGIN
 BEGIN
  PERFORM verivaro_identity.register_session('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abf',clock_timestamp()-interval '1 second',clock_timestamp()+interval '20 minutes');
  RAISE EXCEPTION 'disabled actor registered session';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $disabled$;
RESET ROLE;
SET ROLE verivaro_recovery_service;
SELECT verivaro_identity.recover_actor('12345678-1234-4234-8234-123456789abc','32345678-1234-4234-8234-123456789abc');
RESET ROLE;
SET ROLE verivaro_identity_service;
DO $stale$
BEGIN
 BEGIN
  PERFORM verivaro_identity.register_session('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abf',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '20 minutes');
  RAISE EXCEPTION 'stale upstream authentication restored identity';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $stale$;
SELECT verivaro_identity.register_session('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abf',clock_timestamp(),clock_timestamp()+interval '20 minutes');
DO $duplicate$
BEGIN
 BEGIN
  PERFORM verivaro_identity.register_session('12345678-1234-4234-8234-123456789abc','12345678-1234-4234-8234-123456789abd',clock_timestamp(),clock_timestamp()+interval '20 minutes');
  RAISE EXCEPTION 'old session restored';
 EXCEPTION WHEN unique_violation THEN NULL; END;
END $duplicate$;
RESET ROLE;
SET ROLE verivaro_recovery_service;
SELECT verivaro_identity.disable_actor('12345678-1234-4234-8234-123456789abc');
DO $replay$
BEGIN
 BEGIN
  PERFORM verivaro_identity.recover_actor('12345678-1234-4234-8234-123456789abc','32345678-1234-4234-8234-123456789abc');
  RAISE EXCEPTION 'recovery approval replay succeeded';
 EXCEPTION WHEN unique_violation THEN NULL; END;
END $replay$;
RESET ROLE;
DO $audit$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id='12345678-1234-4234-8234-123456789abc')
 OR EXISTS(SELECT 1 FROM verivaro_private.identity_sessions WHERE actor_id='12345678-1234-4234-8234-123456789abc' AND revoked_at IS NULL)
 OR (SELECT count(*) FROM verivaro_private.identity_events WHERE actor_id='12345678-1234-4234-8234-123456789abc')<>7
 THEN RAISE EXCEPTION 'recovery rollback or audit history mismatch'; END IF;
 BEGIN
  DELETE FROM verivaro_private.identity_events;
  RAISE EXCEPTION 'audit deletion succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $audit$;
