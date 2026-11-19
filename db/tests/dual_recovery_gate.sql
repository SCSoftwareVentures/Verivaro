-- Synthetic principals; SET SESSION AUTHORIZATION exercises real login binding,
-- not caller-supplied names. No test login credentials are provisioned.
CREATE ROLE vv_ci_reviewer_one NOLOGIN;
CREATE ROLE vv_ci_reviewer_two NOLOGIN;
CREATE ROLE vv_ci_reviewer_target NOLOGIN;
CREATE ROLE vv_ci_reviewer_unmapped NOLOGIN;
GRANT verivaro_recovery_approver TO vv_ci_reviewer_one,vv_ci_reviewer_two,vv_ci_reviewer_target,vv_ci_reviewer_unmapped;
INSERT INTO verivaro_private.recovery_operators(login_name,actor_id) VALUES
 ('vv_ci_reviewer_one','10000000-0000-4000-8000-000000000001'),
 ('vv_ci_reviewer_two','10000000-0000-4000-8000-000000000002'),
 ('vv_ci_reviewer_target','10000000-0000-4000-8000-000000000003');
DO $acl$
BEGIN
 IF has_function_privilege('verivaro_recovery_service','verivaro_identity.approve_recovery(uuid)','EXECUTE')
 OR has_function_privilege('verivaro_recovery_approver','verivaro_identity.recover_actor(uuid,uuid)','EXECUTE')
 OR has_function_privilege('verivaro_identity_service','verivaro_identity.request_recovery(uuid,uuid)','EXECUTE')
 OR has_schema_privilege('verivaro_runtime','verivaro_identity','USAGE')
 OR has_schema_privilege('verivaro_recovery_approver','verivaro_private','USAGE')
 OR has_table_privilege('verivaro_recovery_service','verivaro_private.recovery_operators','INSERT')
 OR has_table_privilege('verivaro_recovery_approver','verivaro_private.recovery_approvals','INSERT')
 THEN RAISE EXCEPTION 'recovery ACL boundary broken'; END IF;
END $acl$;

SET ROLE verivaro_recovery_service;
SELECT verivaro_identity.disable_actor('10000000-0000-4000-8000-000000000003');
SELECT verivaro_identity.request_recovery('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001');
DO $denied$
BEGIN
 BEGIN
  PERFORM verivaro_identity.recover_actor('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001');
  RAISE EXCEPTION 'zero-approval recovery succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  PERFORM verivaro_identity.recover_actor('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000099');
  RAISE EXCEPTION 'arbitrary approval UUID accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $denied$;
RESET ROLE;

SET SESSION AUTHORIZATION vv_ci_reviewer_target;
SET ROLE verivaro_recovery_approver;
DO $self$
BEGIN
 BEGIN
  PERFORM verivaro_identity.approve_recovery('20000000-0000-4000-8000-000000000001');
  RAISE EXCEPTION 'self approval accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $self$;
RESET ROLE;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION vv_ci_reviewer_unmapped;
SET ROLE verivaro_recovery_approver;
DO $unmapped$
BEGIN
 BEGIN
  PERFORM verivaro_identity.approve_recovery('20000000-0000-4000-8000-000000000001');
  RAISE EXCEPTION 'unmapped login approval accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $unmapped$;
RESET ROLE;
RESET SESSION AUTHORIZATION;

SET SESSION AUTHORIZATION vv_ci_reviewer_one;
SET ROLE verivaro_recovery_approver;
SELECT verivaro_identity.approve_recovery('20000000-0000-4000-8000-000000000001');
DO $duplicate$
BEGIN
 BEGIN
  PERFORM verivaro_identity.approve_recovery('20000000-0000-4000-8000-000000000001');
  RAISE EXCEPTION 'duplicate approval accepted';
 EXCEPTION WHEN unique_violation THEN NULL; END;
END $duplicate$;
RESET ROLE;
RESET SESSION AUTHORIZATION;
SET ROLE verivaro_recovery_service;
DO $one$
BEGIN
 BEGIN
  PERFORM verivaro_identity.recover_actor('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001');
  RAISE EXCEPTION 'single approval recovery succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $one$;
RESET ROLE;

SET SESSION AUTHORIZATION vv_ci_reviewer_two;
SET ROLE verivaro_recovery_approver;
SELECT verivaro_identity.approve_recovery('20000000-0000-4000-8000-000000000001');
RESET ROLE;
RESET SESSION AUTHORIZATION;
UPDATE verivaro_private.recovery_operators SET active=false WHERE login_name='vv_ci_reviewer_two';
SET ROLE verivaro_recovery_service;
DO $inactive$
BEGIN
 BEGIN
  PERFORM verivaro_identity.recover_actor('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001');
  RAISE EXCEPTION 'inactive operator approval counted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $inactive$;
RESET ROLE;
UPDATE verivaro_private.recovery_operators SET active=true WHERE login_name='vv_ci_reviewer_two';
SET ROLE verivaro_recovery_service;
SELECT verivaro_identity.request_recovery('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000002');
SELECT verivaro_identity.recover_actor('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001');
SELECT verivaro_identity.disable_actor('10000000-0000-4000-8000-000000000003');
DO $replay$
BEGIN
 BEGIN
  PERFORM verivaro_identity.recover_actor('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000001');
  RAISE EXCEPTION 'consumed request replay succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $replay$;
RESET ROLE;
SET SESSION AUTHORIZATION vv_ci_reviewer_one;
SET ROLE verivaro_recovery_approver;
DO $stale$
BEGIN
 BEGIN
  PERFORM verivaro_identity.approve_recovery('20000000-0000-4000-8000-000000000002');
  RAISE EXCEPTION 'previous lockdown request approved';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $stale$;
RESET ROLE;
RESET SESSION AUTHORIZATION;
-- Expiry fixture: privileged CI inserts an already expired request.
INSERT INTO verivaro_private.recovery_requests
 SELECT '20000000-0000-4000-8000-000000000003',actor_id,lockdown_id,clock_timestamp()-interval '20 minutes',clock_timestamp()-interval '5 minutes'
 FROM verivaro_private.disabled_actors WHERE actor_id='10000000-0000-4000-8000-000000000003';
INSERT INTO verivaro_private.recovery_approvals(request_id,approver_id,approved_at) VALUES
 ('20000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000001',clock_timestamp()-interval '10 minutes'),
 ('20000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000002',clock_timestamp()-interval '10 minutes');
SET ROLE verivaro_recovery_service;
DO $expired$
BEGIN
 BEGIN
  PERFORM verivaro_identity.recover_actor('10000000-0000-4000-8000-000000000003','20000000-0000-4000-8000-000000000003');
  RAISE EXCEPTION 'expired approved request accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $expired$;
RESET ROLE;
DO $audit$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM verivaro_private.disabled_actors WHERE actor_id='10000000-0000-4000-8000-000000000003')
 OR (SELECT count(*) FROM verivaro_private.identity_events WHERE authorization_ref='20000000-0000-4000-8000-000000000001')<>1
 THEN RAISE EXCEPTION 'lockdown or recovery audit mismatch'; END IF;
 BEGIN
  TRUNCATE verivaro_private.recovery_approvals;
  RAISE EXCEPTION 'approval history truncation accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $audit$;
