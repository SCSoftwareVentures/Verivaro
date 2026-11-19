-- Additional adversarial checks for G1; run after tenant_isolation.sql.
-- Setup a new active tenant-A contributor because the previous script revokes actor A.
RESET ROLE;
INSERT INTO verivaro.memberships(tenant_id,actor_id,role)
VALUES ('11111111-1111-4111-8111-111111111111','cccccccc-cccc-4ccc-8ccc-cccccccccccc','contributor');
SET ROLE verivaro_runtime;
BEGIN;
RESET ROLE;
SELECT verivaro_private.ci_sign('11111111-1111-4111-8111-111111111111','cccccccc-cccc-4ccc-8ccc-cccccccccccc',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context', :'signed', true);
DO $$
DECLARE n integer;
BEGIN
  SELECT count(*) INTO n FROM verivaro.projects WHERE tenant_id='22222222-2222-4222-8222-222222222222';
  IF n <> 0 THEN RAISE EXCEPTION 'cross-tenant SELECT succeeded'; END IF;
  BEGIN
    INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by)
    VALUES ('66666666-6666-4666-8666-666666666666',
      '22222222-2222-4222-8222-222222222222',
      '44444444-4444-4444-8444-444444444444',
      repeat('b',64),'quarantine://synthetic/b',
      'cccccccc-cccc-4ccc-8ccc-cccccccccccc');
    RAISE EXCEPTION 'cross-tenant INSERT unexpectedly succeeded';
  EXCEPTION WHEN insufficient_privilege OR check_violation THEN NULL;
  END;
END $$;
ROLLBACK;
-- Viewer can see own project, but cannot submit evidence.
BEGIN;
RESET ROLE;
SELECT verivaro_private.ci_sign('22222222-2222-4222-8222-222222222222','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',pg_backend_pid(),pg_current_xact_id()::text) AS signed \gset
SET ROLE verivaro_runtime;
SELECT set_config('verivaro.signed_context', :'signed', true);
DO $$
DECLARE n integer;
BEGIN
  SELECT count(*) INTO n FROM verivaro.projects;
  IF n <> 1 THEN RAISE EXCEPTION 'viewer read isolation failed'; END IF;
  BEGIN
    INSERT INTO verivaro.evidence(id,tenant_id,project_id,sha256,storage_ref,created_by)
    VALUES ('77777777-7777-4777-8777-777777777777',
      '22222222-2222-4222-8222-222222222222',
      '44444444-4444-4444-8444-444444444444',
      repeat('c',64),'quarantine://synthetic/c',
      'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
    RAISE EXCEPTION 'viewer INSERT unexpectedly succeeded';
  EXCEPTION WHEN insufficient_privilege OR check_violation THEN NULL;
  END;
END $$;
ROLLBACK;
RESET ROLE;
